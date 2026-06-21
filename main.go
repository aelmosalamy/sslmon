// Command sslmon monitors Certificate Transparency for a domain's TLS
// certificates: it lists the ones that already exist (via the crt.sh search
// index) and tails the CT logs for new ones as they are issued.
//
// All command logic lives in package cmd; this file is only the entry point.
package main

import (
	"os"

	"sslmon/cmd"
)

func main() {
	os.Exit(cmd.Main(os.Args[1:]))
}
