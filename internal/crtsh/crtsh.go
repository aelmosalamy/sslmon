// Package crtsh queries crt.sh — a Certificate Transparency search index run by
// Sectigo — for the certificates already issued to a domain.
//
// Raw CT logs cannot be searched by domain, so this is how sslmon answers "what
// certificates exist right now?". It connects to crt.sh's public, read-only
// PostgreSQL service and runs the same full-text query the website uses. The
// live tailer (package monitor) handles new certificates; crt.sh provides the
// historical baseline.
package crtsh

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DefaultConnString points at crt.sh's public, read-only PostgreSQL endpoint.
const DefaultConnString = "postgres://guest@crt.sh:5432/certwatch"

// Cert is one certificate as recorded by crt.sh.
type Cert struct {
	ID         int64     `json:"crtsh_id"` // crt.sh certificate id
	CommonName string    `json:"common_name"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial_number"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Names      []string  `json:"names"` // SAN dNSNames
}

// URL is the crt.sh web page for this certificate.
func (c Cert) URL() string {
	return fmt.Sprintf("https://crt.sh/?id=%d", c.ID)
}

// Client queries a crt.sh PostgreSQL endpoint.
type Client struct {
	connString string
}

// New returns a Client for the given connection string. An empty string uses
// the public crt.sh endpoint.
func New(connString string) *Client {
	if connString == "" {
		connString = DefaultConnString
	}
	return &Client{connString: connString}
}

// queryByDomain finds certificates whose identities match the domain (and its
// subdomains, via crt.sh's full-text index), issued on or after `since`.
//
// It first resolves matching certificate ids through the indexed full-text
// search, then computes the (expensive) x509 accessors only on that small set.
// This keeps the query well under a second, which matters: crt.sh's public
// endpoint is a hot standby that cancels long queries when they conflict with
// replication. crt.sh blocks direct access to certificate_identity, so the
// full-text path is the supported way to search.
const queryByDomain = `
WITH matched AS (
    SELECT DISTINCT cai.CERTIFICATE_ID AS id
    FROM certificate_and_identities cai
    WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
)
SELECT c.ID                                              AS id,
       x509_commonName(c.CERTIFICATE)                    AS common_name,
       ca.NAME                                           AS issuer,
       encode(x509_serialNumber(c.CERTIFICATE), 'hex')   AS serial,
       x509_notBefore(c.CERTIFICATE)                     AS not_before,
       x509_notAfter(c.CERTIFICATE)                      AS not_after,
       ARRAY(SELECT x509_altNames(c.CERTIFICATE))        AS names
FROM matched m
JOIN certificate c ON c.ID = m.id
JOIN ca ON ca.ID = c.ISSUER_CA_ID
WHERE x509_notBefore(c.CERTIFICATE) >= $2
ORDER BY x509_notBefore(c.CERTIFICATE) DESC
LIMIT $3`

// Query returns certificates for the domain and its subdomains issued on or
// after `since`, newest first, capped at limit. The caller is expected to apply
// precise name matching and de-duplication.
func (c *Client) Query(ctx context.Context, domain string, since time.Time, limit int) ([]Cert, error) {
	cfg, err := pgx.ParseConfig(c.connString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	// crt.sh sits behind PgBouncer in transaction-pooling mode, which doesn't
	// support the prepared statements pgx uses by default.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to crt.sh: %w", err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, queryByDomain, domain, since, limit)
	if err != nil {
		return nil, fmt.Errorf("query crt.sh: %w", err)
	}
	defer rows.Close()

	var certs []Cert
	for rows.Next() {
		// Every nullable column is scanned through a pointer (and the SAN array
		// through []*string for NULL elements): a single NULL must not fail the
		// scan and abort the whole result set.
		var (
			cert       Cert
			commonName *string
			issuer     *string
			serial     *string
			notBefore  *time.Time
			notAfter   *time.Time
			names      []*string
		)
		if err := rows.Scan(&cert.ID, &commonName, &issuer, &serial, &notBefore, &notAfter, &names); err != nil {
			return nil, fmt.Errorf("scan crt.sh row: %w", err)
		}
		if commonName != nil {
			cert.CommonName = *commonName
		}
		if issuer != nil {
			cert.Issuer = *issuer
		}
		if serial != nil {
			cert.Serial = *serial
		}
		if notBefore != nil {
			cert.NotBefore = *notBefore
		}
		if notAfter != nil {
			cert.NotAfter = *notAfter
		}
		for _, n := range names {
			if n != nil {
				cert.Names = append(cert.Names, *n)
			}
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read crt.sh rows: %w", err)
	}
	return certs, nil
}
