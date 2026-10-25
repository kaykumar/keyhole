# Keyhole

**See the weak link in your chain of trust.**

Keyhole finds weak and compromised certificate keys and trust-store exposure
across your code, dependencies, and signed artifacts.

It detects low-entropy CA and code-signing keys that can be recovered straight
from the public certificate — the class of failure behind the
[eMudhra CA key compromise](https://www.helpnetsecurity.com/2026/10/21/emudhra-certificates-private-keys-compromised/)
of October 2026 — matches known-bad fingerprints, and audits your certificates
for anything that still trusts them. It runs as a CLI, a GitHub Action, or a
container, with **no SaaS** and pluggable compute for scanning at scale in your
own cloud.

---

## How it works

Keyhole's headline check is cryptographic, not a blocklist lookup.

A healthy elliptic-curve private key is an enormous random number. In the
eMudhra compromise, a broken key-generation ceremony produced private keys that
were tiny integers (values like 4, 56, and 115), recoverable in under a second
from the public certificate. If a public key `Q` equals `d·G` for some small
scalar `d`, then **`d` is the private key**.

Keyhole brute-forces `d` over a small range and checks whether `d·G` reproduces
the certificate's public point. A match is decisive — the key is weak and the
private scalar is recovered. This catches the whole *class* of low-entropy keys,
not just a list of certificates someone already enumerated.

Alongside that, Keyhole matches certificates against a blocklist of known
compromised fingerprints (embedded, and overridable with your own file).

## What it scans today

- Certificate files and bundles: `.pem`, `.crt`, `.cer`, `.der`, `.cert`,
  `.ca-bundle`, and common trust bundles such as `cacert.pem` / `cacerts`.
- A single file, or a directory tree (recursively).

See the [roadmap](#roadmap) for signed-artifact, dependency-manifest, and
trust-store-enumeration scanning.

## Install

```sh
# Go toolchain
go install github.com/kaykumar/keyhole/cmd/keyhole@latest

# or run with Docker — no toolchain needed
docker run --rm -v "$PWD:/src" ghcr.io/kaykumar/keyhole:latest scan /src
```

Prebuilt binaries are published on the [Releases](https://github.com/kaykumar/keyhole/releases) page.

## Usage

```sh
keyhole scan <path>                         # scan a file or directory (text output)
keyhole scan --format sarif --output out.sarif .
keyhole scan --fail-on high .               # exit non-zero when a finding is >= high
keyhole scan --max-scalar 1048576 certs/    # widen the weak-key search
keyhole scan --blocklist my-blocklist.json . # use your own fingerprint list
```

Flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--format` | `text` | `text` or `sarif` |
| `--output` | `-` | output file, or `-` for stdout |
| `--blocklist` | embedded | path to a fingerprint blocklist JSON |
| `--max-scalar` | `65536` | upper bound for the weak-key scalar search |
| `--fail-on` | `none` | exit non-zero at `critical\|high\|warning\|note\|none` |

## GitHub Action

Zero local install — it runs on your own runners, and your code never leaves
GitHub. Copy [`examples/github-workflow.yml`](examples/github-workflow.yml) into
`.github/workflows/`:

```yaml
- uses: actions/checkout@v4
- uses: kaykumar/keyhole@main        # pin to a release tag in production
  with:
    path: .
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: keyhole.sarif
```

Findings show up in the repository's **Security → Code scanning** tab and inline
on pull requests.

## Updating the blocklist

The embedded blocklist ships with the eMudhra intermediate CA names as
placeholders but **without fingerprints** — Keyhole will not invent
security-critical hashes. Populate the `sha256` fields from an authoritative
source before relying on fingerprint matching:

- [CCADB](https://www.ccadb.org/) and Mozilla OneCRL
- Vendor blocklists (for example the JDK `blocked.certs` list)

Then point Keyhole at it with `--blocklist your-blocklist.json`. The weak-key
detector works independently and needs no blocklist.

## Design: no SaaS

Keyhole runs entirely on your side. There is no hosted service and no backend
to trust with your code:

- **GitHub Action** on your runners — you host nothing.
- **CLI / Docker image** for local and ad-hoc runs.
- **Bring your own compute** (planned) — dispatch scans to your own AWS
  (Lambda/Fargate), Kubernetes, or other backend through a small provider
  interface, so you can scan at scale inside your own boundary.

Keyhole is a **static** analyzer: it parses certificates and never executes the
code or artifacts it scans.

## Roadmap

- Signed-artifact scanning: Authenticode (PE) and Java JAR signature chains,
  including the RFC 3161 timestamp window (the "valid despite revocation" case).
- Dependency and config scanning: lockfiles (`certifi`, `go.sum`, …),
  Dockerfiles, and CI signing config.
- Trust-store enumeration: OS stores, the JVM `cacerts`, Node, Go, Python
  `certifi`.
- RSA weak-key heuristics (small keys, shared factors).
- Pluggable sandbox providers (local Docker, AWS Fargate/Lambda, Kubernetes).
- A self-hostable GitHub App for org-wide, zero-config scanning.
- Signed releases (cosign / SLSA provenance) and a signed, versioned blocklist.

## License

[Apache-2.0](LICENSE).
