// Package cmd implements sslmon's command-line interface. main.go is only a
// shim that calls Main; everything else lives here so the root package stays
// trivial.
//
// The interface is deliberately tiny: the common case — "show me a domain's
// certificates" — needs no subcommand, just `sslmon <domain>`. `watch` and
// `logs` are the only verbs.
package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
)

// Main parses the command line and dispatches. It returns a process exit code.
//
// The first argument selects a verb (watch, logs); anything else is treated as
// the default list action, so `sslmon example.com` and `sslmon -i` just work.
func Main(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	case "watch":
		return exit(runWatch(ctx, args[1:]))
	case "logs":
		return exit(runLogs(ctx, args[1:]))
	case "list", "query": // explicit aliases for the default action
		return exit(runList(ctx, args[1:]))
	default:
		return exit(runList(ctx, args))
	}
}

func exit(err error) int {
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp), errors.Is(err, context.Canceled):
		return 0
	default:
		fmt.Fprintln(os.Stderr, "sslmon:", err)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "sslmon — Certificate Transparency monitoring for a domain")
	fmt.Fprintln(w, "\nUsage:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  sslmon <domain> [flags]\tlist a domain's certificates")
	fmt.Fprintln(tw, "  sslmon watch <domain> [flags]\twatch for newly-issued certificates")
	fmt.Fprintln(tw, "  sslmon logs [flags]\tlist the CT logs (advanced)")
	tw.Flush()
	fmt.Fprintln(w, "\nList flags:  -since 1y · -only-domain · -valid · -all · -i · -f txt|tsv|json · -o file")
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  sslmon example.com                 # matching subdomains, newest first")
	fmt.Fprintln(w, "  sslmon example.com -since 3m       # only the last 3 months")
	fmt.Fprintln(w, "  sslmon example.com -f json > out   # full records as JSON")
	fmt.Fprintln(w, "  sslmon example.com -i              # browse them interactively")
	fmt.Fprintln(w, "\nRun \"sslmon <command> -h\" for all flags.")
}

// newFlagSet returns a FlagSet whose usage shows the command and a one-line
// description above the flags. Flags use the Go standard library's flag package
// (both -flag and --flag are accepted). Usage is written to the set's output
// (stderr by default; stdout when help is explicitly requested).
func newFlagSet(name, usageLine, desc string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\n\nUsage:\n  sslmon %s\n\nFlags:\n", desc, usageLine)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses fs, allowing flags and positional arguments to be
// interspersed — the standard flag package otherwise stops at the first
// non-flag argument, which would break "sslmon example.com -since 3m". It
// returns the positional arguments in their original order.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return positionals, nil
}

// wantsHelp reports whether args contain a help flag, before any "--"
// terminator. It is checked before parsing so that -h/--help always wins, even
// alongside other or invalid flags.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// showHelp prints the command's usage to stdout and returns true when args
// request help. Commands call it before Parse so help takes priority over
// everything else.
func showHelp(fs *flag.FlagSet, args []string) bool {
	if !wantsHelp(args) {
		return false
	}
	fs.SetOutput(os.Stdout)
	fs.Usage()
	return true
}
