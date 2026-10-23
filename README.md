# emudhra-container-scanner

`emudhra-container-scanner scan IMAGE` pulls a container image straight from
its registry, flattens its filesystem and reports every CA certificate
affected by the October 2026 eMudhra key compromise, in every trust store the
image carries: the system CA bundle and the per-CA source files it is
generated from, Java `cacerts`, Python certifi (and pip's vendored copy), the
bundles shipped by other libraries and tools, NSS databases, p11-kit trust
sources and the root stores compiled into runtime binaries such as Node.js,
Deno and Bun.

For each certificate it says where it sits, whether the image actually trusts
it and for which purposes, which programs consume that store and what to do
about it, and it compares the installed `ca-certificates`, certifi, pip, JDK,
Node.js, Go, Deno and Bun versions with the releases that fixed the incident.

```
$ emudhra-container-scanner scan python:3.12-slim-bookworm
...
OS:        Debian GNU/Linux 12 (bookworm)
Packages (dpkg):
  ca-certificates            20250419~deb12u2  dpkg  ok (fixed in 20250419~deb12u2)
  certifi (vendored in pip)  2024.8.30         pip   OUTDATED: fixed in 2026.10.18
  pip                        25.0.1            pip   OUTDATED: fixed in 26.2.2

Findings (2 high, 9 low; 5 distinct certificates):

/usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem
  [HIGH] AAA Certificate Services (Comodo AAA Services root) (anchor, fingerprint match)
         subject: CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
         sha256:  d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4
         trust:   trusted - pip vendored certifi bundle: certificates in this store are trusted without
                  further configuration
  [HIGH] emSign ECC Root CA - G3 (anchor, fingerprint match)
         ...
  store: pip vendored certifi bundle (app-bundle, python); consumers: pip
  remediation: Upgrade pip to 26.2.2 or later (python -m pip install -U pip) or set PIP_CERT to a fixed
               bundle.
...
Exit code: 2 (findings at or above high; highest is high)
```

No Docker daemon is needed. Registry credentials are read from
`~/.docker/config.json` (and credential helpers) when an image is private.

## Background: the eMudhra compromise

On 17 October 2026 it became public that eight eMudhra intermediate CAs
generated in a flawed key ceremony on 30 April 2025 (EM DV/OV/EV TLS CA - G3B
and G3C, EM OV CS CA - G3B and G3C) have P-384 private keys that anyone can
recover from the public certificates. The intermediates are issued by
"emSign Root TLS CA - G3" and "emSign Root CS CA - G3", which chain to the
publicly trusted root "emSign ECC Root CA - G3", and each of them is also
cross-signed by Sectigo's "AAA Certificate Services" root. eMudhra revoked them
on 18 and 19 October (reason `caCompromise`), but most TLS clients inside
containers never check revocation, so any store that still trusts one of the
two roots accepts certificates forged with the leaked keys.

The ecosystem responded by distrusting the roots and blocking the keys:
Mozilla removed emSign ECC Root CA - G3 (NSS 3.131.1) and pushed the 16
intermediates to OneCRL; Chrome removes the root from the Chrome Root Store on
27 October; Go 1.27.3 / 1.26.10 hard-code the eight public-key hashes in
`crypto/x509`; Debian, Ubuntu, Alpine, Fedora and Arch shipped
`ca-certificates` packages that drop both "emSign ECC Root CA - G3" and
"Comodo AAA Services root"; certifi 2026.10.18, Node.js 22.23.4 / 24.22.1 /
26.12.1, OpenJDK 27.0.1.0.2 / 25.0.5.0.2 / 21.0.13.0.2 / 17.0.21.0.2,
webpki-roots 1.0.10 and rustls-webpki 0.103.16, Deno 2.9.8, Bun 1.4.4,
Electron, Mozilla::CA and composer/ca-bundle followed. Red Hat's fix
(RHSB-2026-012) and the Java 8 and 11 releases were still pending when this
scanner's data was assembled on 22 and 23 October 2026. The sources are listed
at the end of this file.

A container image is affected when any trust store in it still contains one
of the compromised intermediates or one of the roots that anchor them, or when
it runs a binary with its own copy of those roots compiled in. The scanner
answers exactly that question.

## What the scanner looks for

The built-in blocklist (`internal/blocklist/data/entries.json`, version
2026-10-22) has three categories:

| Category | Entries | Severity |
|---|---|---|
| `compromised-key` | the 8 intermediates with recoverable keys and their 8 Sectigo cross-signs (16 certificates, 8 distinct public keys, the same keys Go 1.27.3 blocks) | critical when present and not distrusted |
| `anchor` | emSign ECC Root CA - G3, AAA Certificate Services, emSign Root TLS CA - G3, emSign Root CS CA - G3 and the two cross-certificates of the sub-roots | high when trusted for TLS |
| `related` | 13 other eMudhra roots (emSign Root CA - G1, C1, ECC Root CA - C3 and the Microsoft-program roots) that are not known to be compromised | low, for awareness |

A certificate matches by SHA-256 fingerprint, by public key (so a re-issued or
cross-signed copy of a compromised intermediate is caught), as a bare
SubjectPublicKeyInfo pattern (the form Rust webpki-roots and similar trust
anchor tables embed in binaries) or, for leaf and intermediate certificates
found in the image, by having been issued by a listed CA (signature verified,
reported as `issued-by`). Certificates whose subject merely names
eMudhra/emSign are reported at `info` severity; `--no-operator-heuristic`
turns that off.

Bare public keys of the eight compromised intermediates inside an executable
are recognised as what they are: the SPKI distrust list that fixed runtimes
carry (rustls-webpki 0.103.16, Deno 2.9.8, uv 0.13.5). They are reported at
`info` severity as evidence that the program rejects the leaked keys, not as
an alarm.

### Trust stores

Every regular file in the image is scanned once, so the certificates are found
wherever they live. What the path tells the scanner:

| Store class | Examples | Trust |
|---|---|---|
| `system-bundle` | `/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/pki/ca-trust/extracted/{pem,openssl,java,edk2}/*`, SUSE `/var/lib/ca-certificates/ca-bundle.pem`, Arch `/etc/ca-certificates/extracted`, Nix store bundles | trusted (purpose-specific bundles such as `email-ca-bundle.pem` count only for their purpose) |
| `system-source` | `/usr/share/ca-certificates/**` (selected through `/etc/ca-certificates.conf`), `/usr/share/pki/ca-trust-source/**` (p11-kit `trusted:`/`x-distrusted:` attributes and extended-key-usage restrictions), `certdata.txt` | depends on the configuration; a deselected or distrusted entry is reported at `info` |
| `system-anchor-dir` | `/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`, `/etc/ssl/certs/*.pem` and hash links, SUSE `/var/lib/ca-certificates/pem`, Android `cacerts` | trusted |
| `system-blocklist` | `/etc/pki/ca-trust/source/blocklist`, Arch/SUSE/FreeBSD equivalents | distrusted (`info`); a certificate found here is also marked distrusted wherever else the p11-kit stores carry it |
| `java-keystore` | `cacerts`, `jssecacerts`, `*.jks`, `*.p12`, `*truststore*` (JKS, JCEKS and PKCS#12, password-less or `changeit`/`changeme`/`password`/`--keystore-password`); the `cacerts` generated by `update-ca-trust` or `update-ca-certificates` are tied to the system store | `cacerts` and truststores trusted; other keystores unknown |
| `app-bundle` | Python certifi, pip's vendored certifi, uv, conda, botocore, Perl Mozilla::CA, PHP composer/ca-bundle, RubyGems, gRPC `roots.pem`, curl `curl-ca-bundle.crt`, AWS/Google/Azure CLIs, Erlang certifi/castore (also in OTP release layouts), Homebrew on Linux, ... | trusted by the library that ships it |
| `nss-db` | `cert8.db`, `cert9.db` | unknown (NSS trust flags are per certificate and are not parsed) |
| `embedded-runtime` | `node`, `libnode`, `deno`, `bun`, Electron, Chromium, `libnssckbi.so`, Dart, uv | compiled in, trusted by every program using that runtime (`high`) |
| `embedded-binary` | any other ELF/PE/Mach-O that contains a listed certificate or key | bare trust-anchor tables are `high`; carved certificates of unknown use are `medium` |
| `loose-file` | anything else, e.g. `/app/certs/emsign.pem` | unknown (`medium`) |

A file reached through a link from a trust-store path (for example
`/etc/ssl/certs/ca-certificates.crt -> /opt/custom/bundle.pem`) is classified
by the strongest of its names, and files below a directory symlink
(`/etc/ssl/certs -> /etc/pki/ca-trust/extracted/pem/directory-hash`) get
their aliases too.

Environment variables in the image configuration are taken into account:
`SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`PIP_CERT`, `NODE_EXTRA_CA_CERTS`, `NODE_OPTIONS`, `GIT_SSL_CAINFO`,
`AWS_CA_BUNDLE`, `DENO_CERT`, `JAVA_TOOL_OPTIONS` (`-Djavax.net.ssl.trustStore`)
and friends mark the file they point at as trusted, and variables that disable
verification altogether (`NODE_TLS_REJECT_UNAUTHORIZED=0`,
`PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY`, ...) are reported as warnings.

### Formats

PEM (`CERTIFICATE`, `X509 CERTIFICATE`, OpenSSL `TRUSTED CERTIFICATE` with its
trust/reject attributes, `PKCS7`, also indented inside YAML or source files and
escaped inside JSON), DER certificates anywhere in a file (including inside
executables and `cacerts.bin`), DER and PEM PKCS#7 bundles, JKS/JCEKS
keystores, PKCS#12 keystores, Mozilla `certdata.txt`, p11-kit `.p11-kit`
trust files and bare public-key patterns. Files are streamed in 1 MiB windows,
so image size is not a memory concern; keystores and trust files are parsed
whole up to 64 MiB, and PKCS#12 key derivation is capped so that a crafted
keystore cannot stall the scan.

### Package versions

The package table compares what is installed with the fixed releases:
`ca-certificates` from dpkg (`/var/lib/dpkg/status` and distroless
`status.d`), apk (Alpine and Wolfi) and rpm databases (SQLite on RHEL 9+,
UBI, Fedora and Amazon Linux 2023; ndb on SUSE; Berkeley DB on RHEL 8 and
Amazon Linux 2), certifi and pip from `dist-info` directories and
pip's vendor list, the JDK from its `release` file, Node.js from
`node_version.h`, Go from `/usr/local/go/VERSION`, and Deno, Bun and Node.js
from the image environment or the version string inside the binary. A runtime
that is already at a fixed release is reported as such, and the remediation
does not ask for an upgrade.

## Usage

```
emudhra-container-scanner scan [flags] IMAGE
emudhra-container-scanner version
emudhra-container-scanner help
```

```
emudhra-container-scanner scan debian:latest
emudhra-container-scanner scan --verbose redhat/ubi9
emudhra-container-scanner scan --format json --output report.json python:3.12-slim-bookworm
emudhra-container-scanner scan --platform linux/arm64 --fail-on medium node:20-slim
emudhra-container-scanner scan ghcr.io/org/app@sha256:...
emudhra-container-scanner scan --input ./image.tar              # docker save or OCI archive
emudhra-container-scanner scan --input ./oci-layout app:1.0     # OCI image layout directory
```

| Flag | Meaning |
|---|---|
| `--platform os/arch[/variant]` | platform to select from a multi-platform image (default `linux/<GOARCH>`); a single-platform image is scanned as it is and reported with its own platform |
| `--input PATH` | read a `docker save` tarball, an OCI image archive or an OCI layout directory instead of a registry; `IMAGE` then selects the image inside and may be omitted when the source holds one image |
| `--format text\|json` | report format (default `text`) |
| `--output FILE` | write the report to a file instead of stdout (the file is opened before the pull starts) |
| `--fail-on critical\|high\|medium\|low\|info\|never` | exit 2 when a finding reaches this severity (default `high`) |
| `--blocklist FILE` | PEM or JSON file merged into the built-in blocklist (repeatable) |
| `--keystore-password PW` | extra password to try on PKCS#12 keystores (repeatable; never written into reports) |
| `--no-operator-heuristic` | do not report certificates that merely name eMudhra/emSign |
| `--insecure` | allow plain-HTTP registries and skip registry TLS verification (chains using the compromised keys are still rejected) |
| `--timeout DURATION` | overall limit for pulling and scanning (default 15m) |
| `--quiet` | no progress on stderr |
| `--verbose` | list every store that holds certificates, spell out low/info findings and print explanations and references |

Exit codes: `0` no finding at or above the threshold, `1` usage or runtime
error (message on stderr), `2` findings at or above `--fail-on`. Progress goes
to stderr, the report to stdout (or `--output`).

The registry connection itself refuses TLS chains that use one of the eight
compromised keys, mirroring the Go 1.27.3 mitigation, even with `--insecure`.

## Container image

Every release is also published as a multi-platform (linux/amd64,
linux/arm64) image on GitHub Container Registry:

```
docker run --rm ghcr.io/yanni8/emudhra-container-scanner:latest scan debian:latest
docker run --rm ghcr.io/yanni8/emudhra-container-scanner:latest scan --format json node:20-slim > report.json
```

The image runs as a non-root user (uid 65532) with `/work` as its working
directory. Mount a `docker save` tarball or an OCI layout there to scan it
with `--input` (run as yourself, because `docker save -o` writes the tarball
readable only by its owner); for private registries, mount your Docker
credentials and point `DOCKER_CONFIG` at them:

```
docker run --rm --user "$(id -u)" -v "$PWD:/work:ro" ghcr.io/yanni8/emudhra-container-scanner:latest scan --input /work/image.tar
docker run --rm --user "$(id -u)" -e DOCKER_CONFIG=/docker -v "$HOME/.docker:/docker:ro" \
  ghcr.io/yanni8/emudhra-container-scanner:latest scan registry.example.com/app:1.0
```

Build it locally with `docker build -t emudhra-container-scanner .`.

## Reading the report

Severity of a finding:

| Severity | Meaning |
|---|---|
| critical | a compromised intermediate (or any certificate carrying one of the leaked keys) is present in a store that does not distrust it |
| high | a root that anchors the compromised intermediates is trusted for TLS: present in a system bundle, an enabled source file, an anchor directory, a Java truststore, a library bundle, or compiled into a runtime or a bare trust-anchor table |
| medium | an anchor root trusted for code signing only, in a place whose use is unknown (loose file, keystore of unknown purpose, carved from an arbitrary executable), or a certificate issued by a compromised intermediate |
| low | one of the other eMudhra roots in a trusted store, an anchor root trusted for e-mail only, or a certificate issued by an anchor root |
| info | explicitly distrusted or deselected entries, the SPKI distrust list of fixed runtimes, heuristic name matches, related roots in places of unknown use |

Trust states: `trusted`, `distrusted` (blocklist directory, p11-kit
`x-distrusted`, OpenSSL `TRUSTED CERTIFICATE` reject attributes, certdata
`CKT_NSS_NOT_TRUSTED`, SPKI distrust lists), `disabled` (a `!` line in
`/etc/ca-certificates.conf` whose links and bundle were regenerated),
`embedded` (compiled into a binary) and `unknown`. Trust that is limited to
some purposes (an e-mail-only root, a p11-kit object restricted by extended
key usage) is spelled out in the finding.

The JSON report (`--format json`) contains the same information with stable
snake_case keys: `scanner`, `image` (reference, digest, platform, layers,
compressed size), `os`, `packages` (with `fixed_version` and `outdated`),
`env_hints`, `stores`, `findings` (severity, category, match kind, entry,
issuer entry for `issued-by` matches, path and aliases, store, certificate,
trust, explanation, remediation, references), `summary` (counts for all five
severities, `package_database`, `system_bundle_found`), `warnings` and `exit`
(the `--fail-on` threshold, the exit code and any extra blocklists).

## Custom blocklists

`--blocklist FILE` merges additional entries. A PEM file adds every
certificate in it as a `custom` entry (severity high); a JSON file uses the
same schema as `internal/blocklist/data/entries.json` (`id`, `name`,
`category`, `severity`, `sha256`, `spki_sha256`, `pem`, ...). Entries with the
same fingerprint replace the built-in ones.

## Limitations

- Package databases larger than 256 MiB, encrypted or checksummed Berkeley
  DB files and unknown rpm database variants are reported as present but not
  parsed; the trust stores themselves are always scanned.
- Archives are not opened: certificates inside `.jar`, `.zip`, `.whl`, `.gz`,
  `.deb`, `.apk` or `.rpm` files are not seen (the JDK's `lib/security/cacerts`
  is a plain file and is scanned; pip's bundled wheel under `ensurepip` is
  not).
- Encrypted PKCS#12 keystores are only readable with the right password.
  RC4-protected PKCS#12, public-key privacy modes, BER-encoded PKCS#12 and
  JCEKS entries after a secret key are reported as unreadable, as are
  keystores whose key derivation exceeds the scanner's budget.
- NSS databases are carved for certificates but their trust flags are not
  read; check them with `certutil -L`.
- Trust of a library bundle assumes the library that ships it loads it; only
  the environment variables listed above override that.
- The fixed-version table is a snapshot of 23 October 2026 (Chrome's root
  removal lands on 27 October; Red Hat, Java 8 and Java 11 fixes are
  pending). Check the community tracker at
  https://emudhra.we-have-a-problem.com/ for newer releases.
- Only Linux (and Android) filesystem layouts are known to the store
  classifier; Windows images are scanned but every store is reported as a
  loose file or embedded binary.

## Development

```
go build -o emudhra-container-scanner .
go test ./...
```

Packages: `internal/blocklist` (data and matching), `internal/certs`
(certificate finder), `internal/keystore` (JKS and PKCS#12 parsers),
`internal/image` (registry, tarball and OCI layout access),
`internal/rpmdb` (rpm database reader), `internal/stores` (trust-store
catalogue, configuration parsers, fixed versions), `internal/scan`
(filesystem walk, trust resolution, severities), `internal/report` (text and
JSON output).

The blocklist was assembled from the Mozilla incident bug, the Go patch and
crt.sh and cross-checked with the community tracker; every entry carries its
PEM, fingerprints, key identifiers, revocation date, notes and references.
To update it, edit `internal/blocklist/data/entries.json` (the tests check the
integrity of every entry and that the compromised keys match Go's list) and
the fixed versions in `internal/stores/fixes.go`.

## Releases

Pushing a tag runs `.github/workflows/release.yml`:

```
git tag v1.2.3
git push origin v1.2.3
```

The workflow runs the tests, builds the binaries for Linux, macOS and Windows,
builds the image for linux/amd64 and linux/arm64, pushes the image to GHCR and
publishes a GitHub release with the archives, their SHA-256 checksums and
generated release notes. A tag with a pre-release suffix
(`v1.2.3-rc.1`) is published as a pre-release and does not move the `latest`
image tag.

## Sources

- Mozilla incident bug 2083449 (fingerprints of the compromised intermediates
  and cross-signs), bug 2084101 (removal of emSign ECC Root CA - G3), NSS
  3.131.1 release notes
- Google security blog on the eMudhra incident and the Chrome Root Store
  removal
- Go issue golang/go#82345 / CVE-2026-111943 (crypto/x509 key blocklist in
  1.27.3 and 1.26.10)
- Debian DSA-6572-1 and DLA-4845-1, Ubuntu USN-8944-1 and USN-8944-2
  (ca-certificates) and USN-8947-1 (nss), Alpine ca-certificates 20261020-r0,
  Fedora ca-certificates 2026.2.92_v9.0.319-2, Arch ca-certificates-mozilla
  3.131.1-1
- Red Hat RHSB-2026-012 / CVE-2026-114406
- OpenJDK vulnerability advisory of 21 October 2026 (CVE-2026-91403), Perl
  Mozilla::CA CVE-2026-113812
- certifi 2026.10.18 and 2026.10.19, pip 26.2.2, uv 0.13.4 / 0.13.5, Node.js
  22.23.4 / 24.22.1 / 26.12.1, webpki-roots 1.0.10, rustls-webpki 0.103.16,
  Deno 2.9.8, Bun 1.4.4, Electron 44.9.1 / 43.8.1 / 42.11.16,
  composer/ca-bundle 1.6.0 / 1.4.16
- Community tracker: https://emudhra.we-have-a-problem.com/
