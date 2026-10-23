//go:debug x509negativeserial=1

// Command emudhra-container-scanner checks container images for CA
// certificates affected by the October 2026 eMudhra key compromise.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"emudhra-container-scanner/internal/blocklist"
	"emudhra-container-scanner/internal/certs"
	"emudhra-container-scanner/internal/image"
	"emudhra-container-scanner/internal/report"
	"emudhra-container-scanner/internal/scan"
)

// appName is the command name used in messages; it is the scanner name the
// reports carry.
const appName = scan.Name

// errFindings signals that findings reached the --fail-on threshold; the
// report already explained it, so the command exits 2 without a message.
var errFindings = errors.New("findings at or above the failure threshold")

// usageError is a mistake on the command line. It is printed like any other
// error, followed by hint, and exits 1.
type usageError struct {
	msg  string
	hint string
}

func (e usageError) Error() string { return e.msg }

// scanUsageError builds a usage error of the scan command.
func scanUsageError(format string, args ...any) error {
	return usageError{msg: fmt.Sprintf(format, args...), hint: fmt.Sprintf("Run '%s scan --help' for the flags.", appName)}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line, writing reports and usage to stdout and
// errors and progress to stderr, and returns the process exit code: 0 clean,
// 1 usage or runtime error, 2 findings at or above the --fail-on threshold.
func run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout, stderr)
	if err == nil {
		return 0
	}
	if errors.Is(err, errFindings) {
		return 2
	}
	fmt.Fprintf(stderr, "%s: %v\n", appName, err)
	var ue usageError
	if errors.As(err, &ue) && ue.hint != "" {
		fmt.Fprintln(stderr, ue.hint)
	}
	return 1
}

// version is the scanner version: set with -ldflags "-X main.version=..." or
// taken from the module build information.
var version = ""

func scannerVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s: find CA certificates affected by the October 2026 eMudhra key compromise in container images

Usage:
  %s scan [flags] IMAGE      pull IMAGE (or read it from --input) and scan every trust store in it
  %s version                 print the scanner and blocklist versions
  %s help                    show this message

The scan command pulls the image straight from its registry (no Docker daemon needed; credentials come
from ~/.docker/config.json) or reads it from a docker-save tarball, an OCI image layout directory or an
OCI image layout archive (--input), flattens its filesystem and looks for the compromised eMudhra
intermediate CAs, the roots that anchor them ("emSign ECC Root CA - G3", Sectigo's "AAA Certificate
Services", "emSign Root TLS/CS CA - G3") and other eMudhra roots in: system CA bundles and their source
directories, Java cacerts/keystores, Python certifi and other library bundles, NSS databases, p11-kit
trust sources and the root stores compiled into runtime binaries (Node.js, Deno, Chromium, Rust
webpki-roots users). Run "%s scan --help" for the flags.

Exit codes: 0 clean, 1 usage or runtime error, 2 findings at or above --fail-on.
`, appName, appName, appName, appName, appName)
}

// dispatch runs the command named by args.
func dispatch(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s %s (blocklist %s, %s, %s/%s)\n", appName, scannerVersion(), blocklist.Default().Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	case "help", "--help", "-h":
		usage(stdout)
		return nil
	}
	return usageError{msg: fmt.Sprintf("unknown command %q", args[0]), hint: fmt.Sprintf("Run '%s help' for usage.", appName)}
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// scanConfig is the parsed command line of the scan command.
type scanConfig struct {
	ref      string
	platform string
	input    string
	format   string
	output   string
	// failOn is the threshold severity; failEnabled is false for "never".
	// failOnName is the normalised flag value recorded in the report.
	failOn      blocklist.Severity
	failEnabled bool
	failOnName  string
	noOperator  bool
	insecure    bool
	timeout     time.Duration
	quiet       bool
	verbose     bool
	blocklists  []string
	passwords   []string
}

// parseScanArgs parses the scan command line. done is true when the help
// was requested and printed to stdout, in which case there is nothing more
// to do.
func parseScanArgs(args []string, stdout io.Writer) (cfg *scanConfig, done bool, err error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	// Errors are reported once, by run, with a hint; the help goes to
	// stdout on request only.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	cfg = &scanConfig{}
	var (
		format     = fs.String("format", "text", "output format: text or json")
		failOn     = fs.String("fail-on", "high", "exit 2 when a finding is at or above this severity: critical, high, medium, low, info or never")
		blocklists stringList
		passwords  stringList
	)
	fs.StringVar(&cfg.platform, "platform", "", "platform to select from a multi-platform image (os/arch[/variant]); default: the image's own platform for a single-platform image, linux/"+runtime.GOARCH+" for a multi-platform one")
	fs.StringVar(&cfg.input, "input", "", "read the image from a local source instead of a registry: a docker-save tarball, an OCI image layout directory or an OCI image layout archive (buildx -o type=oci, podman save --format oci-archive, skopeo oci-archive:); IMAGE then selects the image inside and may be omitted when the source holds one image")
	fs.StringVar(&cfg.output, "output", "", "write the report to this file instead of stdout (created before the scan starts and removed again if the scan fails)")
	fs.BoolVar(&cfg.noOperator, "no-operator-heuristic", false, "do not report certificates that merely name eMudhra/emSign in their subject")
	fs.BoolVar(&cfg.insecure, "insecure", false, "allow plain-HTTP registries and skip TLS verification (the compromised eMudhra keys are still rejected)")
	fs.DurationVar(&cfg.timeout, "timeout", 15*time.Minute, "overall time limit for pulling and scanning (must be positive)")
	fs.BoolVar(&cfg.quiet, "quiet", false, "do not print progress on stderr")
	fs.BoolVar(&cfg.verbose, "verbose", false, "list every store that holds certificates, spell out low/info findings and add explanations and references")
	fs.Var(&blocklists, "blocklist", "additional blocklist file (PEM or JSON), merged into the built-in list; repeatable")
	fs.Var(&passwords, "keystore-password", "additional password to try on PKCS#12 keystores (defaults: empty, changeit, changeme, password); repeatable")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(stdout, fs)
			return nil, true, nil
		}
		return nil, false, scanUsageError("%v", err)
	}
	rest := fs.Args()
	if len(rest) > 1 {
		for _, a := range rest[1:] {
			if strings.HasPrefix(a, "-") {
				return nil, false, scanUsageError("flags must come before IMAGE: %q was read as an argument after %q", a, rest[0])
			}
		}
		return nil, false, scanUsageError("too many arguments: %s", strings.Join(rest[1:], " "))
	}
	if len(rest) == 1 {
		cfg.ref = rest[0]
	}
	if cfg.ref == "" && cfg.input == "" {
		return nil, false, scanUsageError("an image reference is required (or --input with a local image)")
	}
	cfg.format = strings.ToLower(strings.TrimSpace(*format))
	if cfg.format != "text" && cfg.format != "json" {
		return nil, false, scanUsageError("unknown --format %q (want text or json)", *format)
	}
	cfg.failOnName = strings.ToLower(strings.TrimSpace(*failOn))
	if cfg.failOnName == "never" {
		cfg.failOn, cfg.failEnabled = blocklist.SeverityInfo, false
	} else {
		sev, err := blocklist.ParseSeverity(cfg.failOnName)
		if err != nil {
			return nil, false, scanUsageError("--fail-on: unknown severity %q (want one of critical, high, medium, low, info or never)", *failOn)
		}
		cfg.failOn, cfg.failEnabled, cfg.failOnName = sev, true, sev.String()
	}
	if cfg.timeout <= 0 {
		return nil, false, scanUsageError("--timeout must be positive (got %s)", cfg.timeout)
	}
	cfg.blocklists, cfg.passwords = blocklists, passwords
	return cfg, false, nil
}

// scanUsage prints the scan command's help to w.
func scanUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: %s scan [flags] IMAGE\n\n", appName)
	fmt.Fprintf(w, "IMAGE is a registry reference (debian:latest, ghcr.io/org/app@sha256:...). With --input it selects the\nimage inside a docker-save tarball, an OCI image layout directory or an OCI image layout archive and\nmay be omitted when the source holds one image. Flags must come before IMAGE.\n\nFlags:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	fmt.Fprintf(w, "\nExit codes: 0 clean, 1 usage or runtime error, 2 findings at or above --fail-on (default high).\n")
}

// loadBlocklists merges the user's blocklist files into the built-in list.
func loadBlocklists(paths []string) (*blocklist.List, error) {
	list := blocklist.Default()
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("--blocklist: %w", err)
		}
		extra, err := blocklist.Load(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("--blocklist %s: %w", path, err)
		}
		list = list.Merge(extra)
	}
	return list, nil
}

// outputFile is the --output file. It is created before the image is pulled
// so that an unwritable path fails before any work is done, and removed
// again unless the report was written into it.
type outputFile struct {
	f    *os.File
	path string
	kept bool
}

// createOutput creates the file at path, or returns nil for "" (stdout).
func createOutput(path string) (*outputFile, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("--output: %w", err)
	}
	return &outputFile{f: f, path: path}, nil
}

// writer returns the destination of the report: the file, or fallback.
func (o *outputFile) writer(fallback io.Writer) io.Writer {
	if o == nil {
		return fallback
	}
	return o.f
}

// keep closes the file and keeps it. It reports the close error, which is
// where a full disk may surface.
func (o *outputFile) keep() error {
	if o == nil {
		return nil
	}
	o.kept = true
	if err := o.f.Close(); err != nil {
		return fmt.Errorf("--output: %w", err)
	}
	return nil
}

// discard closes and removes the file unless it was kept.
func (o *outputFile) discard() {
	if o == nil || o.kept {
		return
	}
	o.f.Close()
	os.Remove(o.path)
}

func runScan(args []string, stdout, stderr io.Writer) error {
	cfg, done, err := parseScanArgs(args, stdout)
	if err != nil || done {
		return err
	}
	list, err := loadBlocklists(cfg.blocklists)
	if err != nil {
		return err
	}
	out, err := createOutput(cfg.output)
	if err != nil {
		return err
	}
	defer out.discard()
	keystorePasswords := append(append([]string(nil), certs.DefaultPasswords...), cfg.passwords...)

	progress := func(msg string) { fmt.Fprintf(stderr, "%s: %s\n", appName, msg) }
	if cfg.quiet {
		progress = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	im, err := image.Open(ctx, cfg.ref, image.Options{
		Platform:         cfg.platform,
		Input:            cfg.input,
		Insecure:         cfg.insecure,
		RejectSPKIHashes: list.CompromisedSPKIHashes(),
		Progress:         progress,
	})
	if err != nil {
		return withTimeoutHint(ctx, cfg.timeout, describeOpenError(err))
	}
	// Close removes the temporary directory of an OCI layout archive; it
	// must run after the scan has consumed the filesystem stream.
	defer im.Close()
	res, err := scan.Image(ctx, im, scan.Options{
		Blocklist:                list,
		Progress:                 progress,
		IncludeOperatorHeuristic: !cfg.noOperator,
		KeystorePasswords:        keystorePasswords,
		Version:                  scannerVersion(),
	})
	if err != nil {
		return withTimeoutHint(ctx, cfg.timeout, err)
	}
	res.Exit = exitFor(res, cfg)

	if err := writeReport(out.writer(stdout), cfg, res); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	if err := out.keep(); err != nil {
		return err
	}
	if cfg.output != "" && progress != nil {
		progress(fmt.Sprintf("report written to %s (%s)", cfg.output, report.ExitLine(res, cfg.failOn, cfg.failEnabled)))
	}
	if res.Exit.Code != 0 {
		return errFindings
	}
	return nil
}

// exitFor records the exit decision for the result: the threshold, the
// exit code and the extra blocklists that were merged.
func exitFor(res *scan.Result, cfg *scanConfig) scan.Exit {
	e := scan.Exit{FailOn: cfg.failOnName, ExtraBlocklists: cfg.blocklists}
	if cfg.failEnabled && len(res.Findings) > 0 && res.MaxSeverity() >= cfg.failOn {
		e.Code = 2
	}
	return e
}

// writeReport renders the result in the requested format.
func writeReport(w io.Writer, cfg *scanConfig, res *scan.Result) error {
	if cfg.format == "json" {
		return report.WriteJSON(w, res)
	}
	if err := report.WriteText(w, res, cfg.verbose); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, report.ExitLine(res, cfg.failOn, cfg.failEnabled))
	return err
}

// withTimeoutHint tells the user how to raise the limit when the error was
// caused by the overall timeout, in whichever phase it struck.
func withTimeoutHint(ctx context.Context, timeout time.Duration, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w (timeout %s; raise it with --timeout)", err, timeout)
	}
	return err
}

// describeOpenError keeps the structured errors of the image package
// readable on the command line.
func describeOpenError(err error) error {
	var pnf *image.PlatformNotFoundError
	if errors.As(err, &pnf) {
		return fmt.Errorf("%v (choose one with --platform)", pnf)
	}
	var dk *image.DistrustedKeyError
	if errors.As(err, &dk) {
		return fmt.Errorf("%v; the registry connection was refused because its TLS chain uses a compromised eMudhra key", err)
	}
	return err
}
