package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/config"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/userdirs"
)

const filesHelp = `Without -config, rj-socks reads $XDG_CONFIG_HOME/rj-socks/config.yaml
(~/.config/rj-socks/config.yaml when XDG_CONFIG_HOME is unset or relative; ~ is
%USERPROFILE% on Windows). If that file does not exist it falls back to
config.yaml in the current directory, where older versions kept it, and says so
on stderr; "rj-socks migrate" moves that file to the new location.
`

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, "Usage:\n  rj-socks [-config FILE] [-check-config] [-probe certificate|login]\n  rj-socks -version\n  rj-socks migrate [-dry-run] [-from FILE]\n\n", filesHelp, "\n")
	flag.PrintDefaults()
}

// chooseConfig returns the configuration file to use: -config when it was
// given, otherwise the XDG file or, failing that, ./config.yaml from older
// versions, which is announced once on stderr and never on stdout.
func chooseConfig(env userdirs.Env, flagValue string, explicit bool, stderr io.Writer) (string, error) {
	if explicit {
		return flagValue, nil
	}
	choice, err := env.ResolveConfig()
	if err != nil {
		return "", err
	}
	if choice.Legacy {
		fmt.Fprintln(stderr, choice.LegacyNotice())
	}
	return choice.Path, nil
}

func runMigrate(args []string, env userdirs.Env, stdout io.Writer) error {
	flags := flag.NewFlagSet("rj-socks migrate", flag.ExitOnError)
	dryRun := flags.Bool("dry-run", false, "print the plan and change nothing")
	from := flags.String("from", "", "configuration file to move (default config.yaml in the current directory)")
	flags.Usage = func() {
		out := flags.Output()
		fmt.Fprint(out, `Usage: rj-socks migrate [-dry-run] [-from FILE]

Moves the configuration an older rj-socks read from the current directory (or
FILE) to $XDG_CONFIG_HOME/rj-socks/config.yaml. A relative vpn.tls.ca_file in it
is rewritten as an absolute path so it still finds the CA. An existing file at
the new location is never overwritten: an identical one makes the old copy
redundant and it is removed; a different one is a conflict, both are kept and
migrate exits non-zero. Running it again finds nothing to do.

migrate cannot tell whether rj-socks is running; stop it first.

`)
		flags.PrintDefaults()
	}
	flags.Parse(args)
	if flags.NArg() > 0 {
		return fmt.Errorf("migrate: unexpected argument %q", flags.Arg(0))
	}
	return env.Migrate(userdirs.MigrateOptions{From: *from, DryRun: *dryRun, Rewrite: rewriteCAFile, Out: stdout})
}

func rewriteCAFile(data []byte, dir string) ([]byte, []userdirs.PathRewrite, error) {
	out, oldPath, newPath, changed, err := config.AbsoluteCAFile(data, dir)
	if err != nil || !changed {
		return data, nil, err
	}
	return out, []userdirs.PathRewrite{{Key: "vpn.tls.ca_file", Old: oldPath, New: newPath}}, nil
}
