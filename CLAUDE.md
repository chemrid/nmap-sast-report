# Claude Code Context — nmap-unprivileged SAST Analysis

This file gives a new Claude Code session full context to continue analysis on any machine.

---

## Project Overview

**nmap-unprivileged** is a fork of nmap modified for air-gapped Linux deployments
(RHEL / Astra Linux / Debian) with raw-socket privilege escalation removed.

- **Source repo:** https://github.com/chemrid/nmap-unprivileged
- **SAST results repo:** https://github.com/chemrid/nmap-sast-report (this repo)
- **Commit analysed:** `5da159d77` (branch: master)

### What Was Built

Stripped nmap that works **without root/CAP_NET_RAW**:
- TCP connect scan (`-sT`), service detection (`-sV`), NSE scripts work
- SYN scan (`-sS`), UDP scan (`-sU`), OS detection (`-O`) blocked — print "requires root" and exit
- No nping / ncat / ndiff / zenmap built
- All dependencies bundled: libpcap, libdnet, libpcre, liblua, **OpenSSL 3.4.1**
- JDWP NSE helper `.class` files compiled from `.java` at build time (no binary blobs)

### Files Modified vs Upstream nmap

| File | Change |
|------|--------|
| `nmap.cc` | Removed raw-socket exit guards for `-sS`/`-sU`/`-O` |
| `NmapOps.cc` | Disabled `CAP_NET_RAW`-dependent options |
| `libnetutil/PacketElement.h` | Added `#include <cstring>` after `#include "netutil.h"` (GCC 9+ fix) |
| `libnetutil/netutil.cc` | Fixed include ordering |
| `build-offline.sh` | New: full offline build (CRLF fix + OpenSSL + JDWP javac) |
| `openssl/` | OpenSSL 3.4.1 source tree bundled (Apache 2.0) |

---

## SAST Setup

### Docker Image

```bash
# Image used for all analysis (Debian Bookworm based):
docker image: nmap-sast:latest
# Contains: Cppcheck 2.10, Flawfinder 2.0.19, Semgrep 1.156.0, ShellCheck 0.9.0

# To rebuild on MacBook (Apple Silicon — arm64):
# The Dockerfile is NOT in this repo. Recreate with:
docker run --rm debian:bookworm bash -c "
  apt-get update -q &&
  apt-get install -y cppcheck flawfinder shellcheck python3-pip git &&
  pip3 install semgrep --break-system-packages
"
# Then tag as nmap-sast:latest
```

### Running the Full Analysis

```bash
# Clone source
git clone https://github.com/chemrid/nmap-unprivileged /path/to/nmap-unprivileged

# Run analysis (sources are copied INTO container to avoid slow Docker volume I/O)
docker run --rm --network none \
  -v "/path/to/nmap-unprivileged:/mnt/src:ro" \
  nmap-sast:latest \
  bash -c 'cp -a /mnt/src /src && cd /src && sh sast-report.sh 2>&1'
```

**Note on timing (Docker on Apple Silicon):** Each nmap.cc cppcheck pass takes ~1–2 min on
native Linux/M1. Under Docker-on-Windows (WSL2) it was ~7 min. M1 Mac with native Docker
should be significantly faster.

### Key Script: sast-report.sh

Located at `nmap-unprivileged/sast-report.sh`. Sections:
1. Cppcheck core (24 files, `--max-configs=3 -j4`)
2. **nmap.cc two-pass** (`--max-configs=1`, platform-fixed — see below)
3. Cppcheck our mods (`--max-configs=3`)
4. Flawfinder
5. Semgrep (requires network — shows "parse error" offline)
6. ShellCheck
7. OpenSSL reference scan
8. Delta analysis
9. Summary table

---

## Known Issues and Decisions

### nmap.cc cppcheck hang

**Problem:** `cppcheck --max-configs=10` on `nmap.cc` hangs indefinitely on the
`AI_CANONNAME;AI_NUMERICHOST;AI_PASSIVE;HAVE_GETADDRINFO=0` configuration combination.

**Root cause:** Cppcheck 2.10 combinatorial explosion on getaddrinfo-related `#ifdef` chains.

**Fix applied:** Two-pass approach in `sast-report.sh`:
```bash
# Pass 1: explicit HAVE_GETADDRINFO=0 (compact path)
cppcheck --max-configs=1 -DHAVE_GETADDRINFO=0 -UAI_CANONNAME -UWIN32 ...

# Pass 2: HAVE_GETADDRINFO undefined (default path)
cppcheck --max-configs=1 -UHAVE_GETADDRINFO -UAI_CANONNAME -UWIN32 ...

# Deduplicate
sort -u pass1.txt pass2.txt > combined.txt
```

**Why not HAVE_GETADDRINFO=1:** Activating the getaddrinfo code path makes analysis even
slower (DNS resolver code is very complex).

### CRLF line endings

**Problem:** Source checked out on Windows; autoconf `config.status` uses `$`-anchored sed
that fails on `\r`-terminated lines. `HAVE_GETTIMEOFDAY` stays `#undef` → compile error.

**Fix:** `build-offline.sh` runs `find . -name "*.in" | xargs sed -i 's/\r$//'`
before `./configure`. Do NOT touch `*.ac`/`*.am` — triggers autoconf regeneration.

### OpenSSL `lib` vs `lib64`

**Problem:** OpenSSL Configure defaults to `--libdir=lib64`; nmap's configure only
looks in `lib/`.

**Fix:** `perl Configure --libdir=lib ...` in `build-offline.sh`.

### GitHub Push Protection

OpenSSL test certs (`openssl/demos/smime/cakey.pem`) flagged as "GitHub SSH Private Key".
**Fix:** `openssl/.gitignore` excludes `*.pem`, `*.key`, `*.p12`, `*.pfx`.

---

## Test Results (21/21 passed on Debian Bookworm)

Verified in Docker `--network none`:

| Feature | Expected | Result |
|---------|----------|--------|
| `-sT` TCP connect | Works | ✓ |
| `-sn` host discovery | Works | ✓ |
| `-sV` service detection | Works | ✓ |
| NSE scripts | Works | ✓ |
| `-oX` XML output | Works | ✓ |
| `-oG` grepable output | Works | ✓ |
| `-sS` SYN scan | Rejected ("requires root") | ✓ |
| `-sU` UDP scan | Rejected ("requires root") | ✓ |
| `-O` OS detection | Rejected/skipped | ✓ |
| nping/ncat/ndiff/zenmap | Not built | ✓ |
| OpenSSL symbols in binary | None (`nm` clean) | ✓ |

---

## Possible Next Steps

- [x] Run Semgrep with network access — `p/c` ruleset: **0 findings** (268 files, 2 rules). `p/bash`: 0 findings. Results: `results/semgrep-c-network.json`
- [x] Run `cppcheck --max-configs=5 -DHAVE_GETADDRINFO=1` on nmap.cc — completed on M1 (~2 min). Findings **identical** to pass1+pass2 — no new CWEs in getaddrinfo path. Result: `results/cppcheck-nmap-cc-getaddrinfo1.txt`
- [x] Generate SARIF from Cppcheck XML — `cppcheck_xml_to_sarif.py` converter written; 218 findings, 22 rules → `results/cppcheck.sarif`
- [x] Upload results to GitHub Code Scanning — SARIF uploaded via `gh api`, state: `complete`. Visible at https://github.com/chemrid/nmap-sast-report/security/code-scanning
- [x] Review CWE-788 at `nmap.cc:1658` — **false positive**: `fatal()` (which calls `exit()`) guards the OOB path but cppcheck doesn't track `[[noreturn]]` semantics. No real vulnerability.
- [x] Review CWE-475 in `libnetutil/netutil.cc` (7×) — **upstream noise**: `STRAPP(NULL,NULL)` and `STRAPP("...",NULL)` — variadic args are never read when NULL is passed. Technically UB per standard but safe on all realistic platforms. `// TODO: Needs refactoring` comment present upstream.

---

## Repository Structure

```
nmap-unprivileged/          # Source code (github.com/chemrid/nmap-unprivileged)
├── nmap.cc                 # PRIMARY: raw-socket removal
├── NmapOps.cc              # PRIMARY: disabled raw-scan options
├── libnetutil/
│   ├── PacketElement.h     # PRIMARY: added #include <cstring>
│   └── netutil.cc          # PRIMARY: fixed include order
├── build-offline.sh        # PRIMARY: offline build script
├── openssl/                # OpenSSL 3.4.1 source (Apache 2.0)
├── sast-report.sh          # SAST analysis script
└── test-final.sh           # Functional test script (21 tests)

nmap-sast-report/           # This repo (github.com/chemrid/nmap-sast-report)
├── README.md               # Final SAST report
├── CLAUDE.md               # This file — context for Claude Code
├── results/                # Scanner outputs (native formats)
└── sast-report.sh          # Copy of analysis script
```

---

## GitHub Credentials

- Account: `chemrid`
- Remote name in nmap-unprivileged: `mine`
- Corporate TLS cert required on Windows host: `C:/Users/dlutsiv/corporate-ca.crt`
  - Set via: `git config http.sslCAInfo "C:/Users/dlutsiv/corporate-ca.crt"`
  - On MacBook: standard system certs should work

---

## Docker Images (created on Windows host)

| Image | Base | Purpose |
|-------|------|---------|
| `nmap-sast:latest` | debian:bookworm | SAST tools |
| `nmap-openssl-test:latest` | debian:bookworm + perl + javac | Full build test |
| `nmap-debian-test:latest` | debian:bookworm | Basic build test |
| `nmap-builder-gcc9:latest` | ubuntu:20.04 + GCC 9 | GCC 9 compatibility test |

These images are local only. On MacBook, rebuild `nmap-sast` as described above.

---

## Onboarding Instructions for Claude Code (New Machine)

**Read this section first if this is a fresh session on a new machine.**

### Step 1 — Verify the environment

Run the following checks and report what is missing:

```bash
git --version
gh auth status
docker info
ls ~/projects/nmap-unprivileged/nmap.cc 2>/dev/null || echo "nmap-unprivileged not cloned"
ls ~/projects/nmap-sast-report/README.md 2>/dev/null || echo "nmap-sast-report not cloned"
```

### Step 2 — Clone missing repositories

If either repo is missing, clone it:

```bash
mkdir -p ~/projects
git clone https://github.com/chemrid/nmap-unprivileged ~/projects/nmap-unprivileged
git clone https://github.com/chemrid/nmap-sast-report ~/projects/nmap-sast-report
```

### Step 3 — Build the SAST Docker image if absent

```bash
docker image inspect nmap-sast:latest > /dev/null 2>&1 || docker build -t nmap-sast:latest - <<'EOF'
FROM debian:bookworm
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
      cppcheck flawfinder shellcheck python3-pip git && \
    pip3 install semgrep --break-system-packages && \
    rm -rf /var/lib/apt/lists/*
EOF
```

### Step 4 — Confirm context is loaded

After completing steps 1–3, confirm to the user:
- Which repos are present and at which commit
- Whether the Docker image exists
- What the recommended next action is (see "Possible Next Steps" section above)

Do NOT proceed with any analysis until the user confirms the next step.

### Step 5 — Running a new full scan (if requested)

```bash
docker run --rm \
  -v "$HOME/projects/nmap-unprivileged:/mnt/src:ro" \
  nmap-sast:latest \
  bash -c 'cp -a /mnt/src /src && cd /src && sh sast-report.sh 2>&1'
```

On M1 Mac with native Docker: expect ~1–2 min per nmap.cc pass (vs ~7 min on Windows/WSL2).

Results land in `/tmp/sast-report/` inside the container. To extract:

```bash
CONTAINER=$(docker run -d \
  -v "$HOME/projects/nmap-unprivileged:/mnt/src:ro" \
  nmap-sast:latest \
  bash -c 'cp -a /mnt/src /src && cd /src && sh sast-report.sh')
docker wait $CONTAINER
docker cp $CONTAINER:/tmp/sast-report/. ~/projects/nmap-sast-report/results/
docker rm $CONTAINER
```

After extraction, commit and push updated results:

```bash
cd ~/projects/nmap-sast-report
git add results/
git commit -m "Update SAST results from M1 Mac run"
git push
```
