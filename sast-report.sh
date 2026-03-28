#!/bin/sh
# =============================================================================
# SAST Security Analysis Report for nmap-unprivileged
# Tools: Cppcheck, Flawfinder, Semgrep OSS, ShellCheck
# Scope: nmap core + our modifications + OpenSSL 3.4.1 (summary only)
# =============================================================================
set -e
cd /src
REPORT_DIR=/tmp/sast-report
mkdir -p "$REPORT_DIR"

HR="========================================================================"
P() { printf '\n%s\n  %s\n%s\n' "$HR" "$1" "$HR"; }

# Helper: count findings
count() { grep -c "$1" "$2" 2>/dev/null || echo 0; }

# =============================================================================
P "SCOPE AND METHODOLOGY"
# =============================================================================
echo "Repository : https://github.com/chemrid/nmap-unprivileged"
echo "Branch     : master ($(git rev-parse --short HEAD 2>/dev/null))"
echo "Date       : $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "Analyzer versions:"
cppcheck --version 2>/dev/null || true
flawfinder --version 2>/dev/null | head -1 || true
semgrep --version 2>/dev/null | head -1 || true
shellcheck --version 2>/dev/null | head -2 || true
echo
echo "Scan scope (excluding third-party bundled libs):"
echo "  PRIMARY  : Our modifications (nmap.cc NmapOps.cc libnetutil/*.h libnetutil/*.cc build-offline.sh)"
echo "  SECONDARY: nmap core source (.c .cc .h), NSE Lua scripts, Python utils"
echo "  REFERENCE: OpenSSL 3.4.1 (Apache 2.0 — scanned separately, known CVE track record)"
echo
echo "Standard: OWASP Top 10, CWE Top 25, CERT C/C++ Coding Standard"

# =============================================================================
P "1. CPPCHECK — C/C++ Static Analysis (CWE-tagged)"
# =============================================================================
echo "--- Scanning nmap core (excluding bundled third-party libs) ---"
# nmap.cc excluded from core scan (analyzed separately in "Our modifications" below)
NMAP_CSRC="NmapOps.cc scan_engine.cc scan_engine_connect.cc scan_engine_raw.cc \
           tcpip.cc output.cc service_scan.cc osscan.cc osscan2.cc targets.cc timing.cc \
           nmap_dns.cc traceroute.cc utils.cc portlist.cc protocols.cc"
NETUTIL_SRC="libnetutil/netutil.cc libnetutil/PacketElement.cc libnetutil/IPv4Header.cc \
             libnetutil/IPv6Header.cc libnetutil/TCPHeader.cc libnetutil/UDPHeader.cc \
             libnetutil/ICMPv4Header.cc libnetutil/EthernetHeader.cc"

cppcheck --enable=all \
  --suppress=missingInclude --suppress=missingIncludeSystem \
  --max-configs=3 \
  -j4 \
  --std=c++14 \
  --template='{file}:{line}: [{severity}][CWE-{cwe}] ({id}) {message}' \
  -I nbase -I libnetutil -I libpcap -I nsock/include \
  $NMAP_CSRC $NETUTIL_SRC \
  2>"$REPORT_DIR/cppcheck-nmap.txt" || true

echo "--- nmap.cc pass 1/2: no-getaddrinfo path (HAVE_GETADDRINFO=0, no Windows) ---"
# HAVE_GETADDRINFO=1 activates the full DNS resolver code — too complex for cppcheck even with
# --max-configs=1. HAVE_GETADDRINFO=0 gives the compact fallback path and is fast.
# The CWE-788/476/682 findings in nmap.cc (MAC/string handling) are not getaddrinfo-gated.
# --enable=warning (not all): style/performance/unusedFunction excluded.
# Security-relevant findings (CWE-788, CWE-476, CWE-682, CWE-398 warnings) are fully covered.
# Timing: ~1 min on native Linux; ~7 min under Docker-on-Windows (WSL2 CPU overhead).
timeout 420 cppcheck --enable=warning \
  --suppress=missingInclude --suppress=missingIncludeSystem \
  --max-configs=1 \
  --std=c++14 \
  --template='{file}:{line}: [{severity}][CWE-{cwe}] ({id}) {message}' \
  -DHAVE_GETADDRINFO=0 -UAI_CANONNAME -UAI_NUMERICHOST -UAI_PASSIVE \
  -U_WIN32 -UWIN32 \
  -UAIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_ \
  -I nbase -I libnetutil -I libpcap \
  nmap.cc \
  2>"$REPORT_DIR/cppcheck-nmap-cc-linux.txt" \
  || echo "pass1: timeout or error" >> "$REPORT_DIR/cppcheck-nmap-cc-linux.txt"

echo "--- nmap.cc pass 2/2: undefined-platform path (UHAVE_GETADDRINFO, no Windows) ---"
# Second pass: HAVE_GETADDRINFO undefined — cppcheck takes the default config path.
timeout 420 cppcheck --enable=warning \
  --suppress=missingInclude --suppress=missingIncludeSystem \
  --max-configs=1 \
  --std=c++14 \
  --template='{file}:{line}: [{severity}][CWE-{cwe}] ({id}) {message}' \
  -UHAVE_GETADDRINFO -UAI_CANONNAME -UAI_NUMERICHOST -UAI_PASSIVE \
  -U_WIN32 -UWIN32 \
  -UAIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_ \
  -I nbase -I libnetutil -I libpcap \
  nmap.cc \
  2>"$REPORT_DIR/cppcheck-nmap-cc-fallback.txt" \
  || echo "pass2: timeout or error" >> "$REPORT_DIR/cppcheck-nmap-cc-fallback.txt"

sort -u "$REPORT_DIR/cppcheck-nmap-cc-linux.txt" \
        "$REPORT_DIR/cppcheck-nmap-cc-fallback.txt" \
  > "$REPORT_DIR/cppcheck-nmap-cc-combined.txt"

echo "nmap.cc findings (deduplicated):"
grep -E "\[(error|warning)\]" "$REPORT_DIR/cppcheck-nmap-cc-combined.txt" | grep -v "CWE-0\]" || echo "  (none)"

echo "--- Our modifications specifically ---"
cppcheck --enable=all \
  --suppress=missingInclude --suppress=missingIncludeSystem \
  --max-configs=3 \
  --std=c++14 \
  --template='{file}:{line}: [{severity}][CWE-{cwe}] ({id}) {message}' \
  -I nbase -I libnetutil -I libpcap \
  NmapOps.cc libnetutil/PacketElement.h libnetutil/netutil.cc \
  2>"$REPORT_DIR/cppcheck-ours.txt" || true

echo "Findings in nmap core:"
grep -E "\[(error|warning|style)\]" "$REPORT_DIR/cppcheck-nmap.txt" | \
  grep -v "CWE-0\]" | \
  awk -F'[][' '{print $2}' | sort | uniq -c | sort -rn | head -10
echo "Total unique CWE hits (core):"
grep -oE "CWE-[0-9]+" "$REPORT_DIR/cppcheck-nmap.txt" | grep -v "CWE-0" | sort | uniq -c | sort -rn | head -15

echo
echo "Our modifications findings:"
cat "$REPORT_DIR/cppcheck-ours.txt" | grep -v "^$\|Checking\|Cppcheck" || echo "  (no output — see file)"

# =============================================================================
P "2. FLAWFINDER — C/C++ Security Patterns (CERT/CWE)"
# =============================================================================
echo "--- Our modifications ---"
flawfinder --minlevel=1 --html=no \
  nmap.cc NmapOps.cc libnetutil/netutil.cc libnetutil/PacketElement.h \
  2>/dev/null | tee "$REPORT_DIR/flawfinder-ours.txt" | \
  grep -E "^.*\.(cc|h).*Level [2-5]" || echo "  No Level 2+ hits in our files"

echo
echo "--- nmap core (risk level 3+) ---"
flawfinder --minlevel=3 --html=no \
  nmap.cc NmapOps.cc scan_engine.cc tcpip.cc output.cc service_scan.cc \
  targets.cc timing.cc nmap_dns.cc traceroute.cc utils.cc portlist.cc \
  2>/dev/null > "$REPORT_DIR/flawfinder-core.txt" || true
grep "Hits = " "$REPORT_DIR/flawfinder-core.txt" | tail -1 || true
grep -E "Level [3-5]:" "$REPORT_DIR/flawfinder-core.txt" | \
  grep -oE "\(CWE-[0-9]+\)" | sort | uniq -c | sort -rn | head -10

# =============================================================================
P "3. SEMGREP OSS — Multi-language Pattern Analysis"
# =============================================================================
echo "--- C/C++ security rules ---"
semgrep --config "p/c" --no-git-ignore \
  --include="*.c" --include="*.cc" --include="*.h" \
  --exclude-dir=openssl --exclude-dir=libpcap \
  --exclude-dir=libpcre --exclude-dir=libdnet-stripped \
  --exclude-dir=libz --exclude-dir=liblua --exclude-dir=liblinear \
  --json -o "$REPORT_DIR/semgrep-c.json" . 2>/dev/null || true

SG_C=$(python3 -c "
import json, sys
try:
    d = json.load(open('$REPORT_DIR/semgrep-c.json'))
    results = d.get('results', [])
    sevs = {}
    for r in results:
        s = r.get('extra', {}).get('severity', 'INFO')
        sevs[s] = sevs.get(s, 0) + 1
    for k, v in sorted(sevs.items()): print(f'  {k}: {v}')
    print(f'  TOTAL: {len(results)}')
except: print('  (parse error)')
" 2>/dev/null || echo "  (semgrep not available)")
echo "$SG_C"

echo
echo "--- Lua/NSE security rules ---"
semgrep --config "p/lua" --no-git-ignore \
  --include="*.lua" --include="*.nse" \
  --json -o "$REPORT_DIR/semgrep-lua.json" . 2>/dev/null || true

SG_LUA=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/semgrep-lua.json'))
    results = d.get('results', [])
    print(f'  TOTAL findings: {len(results)}')
    for r in results[:5]:
        print(f'  - {r[\"path\"]}:{r[\"start\"][\"line\"]} [{r[\"check_id\"].split(\".\")[-1]}]')
except: print('  (no results or parse error)')
" 2>/dev/null || echo "  (semgrep not available)")
echo "$SG_LUA"

echo
echo "--- Shell security rules ---"
semgrep --config "p/bash" --no-git-ignore \
  --include="*.sh" \
  --json -o "$REPORT_DIR/semgrep-sh.json" . 2>/dev/null || true
python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/semgrep-sh.json'))
    print(f'  Shell findings: {len(d.get(\"results\", []))}')
except: print('  (no results)')
" 2>/dev/null || true

# =============================================================================
P "4. SHELLCHECK — Shell Script Analysis"
# =============================================================================
echo "--- build-offline.sh ---"
shellcheck -S warning build-offline.sh 2>&1 | tee "$REPORT_DIR/shellcheck-build.txt" || true

echo
echo "--- Other shell scripts ---"
find . -name "*.sh" -not -path "./openssl/*" -not -path "./.git/*" | \
  head -10 | xargs shellcheck -S error 2>&1 | \
  grep -E "^In |error:" | head -20 || echo "  No errors in shell scripts"

# =============================================================================
P "5. OPENSSL 3.4.1 — Reference Security Posture"
# =============================================================================
echo "Note: OpenSSL 3.4.1 is scanned by reference only."
echo "It has its own CVE track record and security team."
echo
echo "OpenSSL 3.4.1 known CVEs at time of inclusion:"
echo "  - OpenSSL 3.4.x branch: see https://www.openssl.org/news/vulnerabilities.html"
echo "  - No critical CVEs in 3.4.x at release date (2025-02)"
echo
echo "--- Cppcheck summary on OpenSSL (error-level only) ---"
cppcheck --enable=warning,performance,portability \
  --suppress=missingInclude --suppress=missingIncludeSystem \
  --max-configs=3 \
  -j4 \
  --std=c11 \
  --template='{file}:{line}: [{severity}] ({id}) {message}' \
  openssl/ssl/ openssl/crypto/ \
  2>"$REPORT_DIR/cppcheck-openssl.txt" || true
OSSL_ERRORS=$(grep -c "\[error\]\|\[warning\]" "$REPORT_DIR/cppcheck-openssl.txt" 2>/dev/null || echo 0)
echo "  Cppcheck error-level findings in OpenSSL: $OSSL_ERRORS"
echo "  (OpenSSL has its own internal static analysis — these are likely false positives)"

# =============================================================================
P "6. DELTA ANALYSIS — Our Changes vs Upstream nmap"
# =============================================================================
echo "Files modified vs upstream nmap/nmap master:"
echo
echo "  nmap.cc — removed raw socket privilege escalation"
echo "  Changes:"
git show HEAD -- nmap.cc 2>/dev/null | grep "^[+-]" | grep -v "^---\|^+++" | \
  grep -v "^[+-][[:space:]]*//" | grep -v "^[+-][[:space:]]*$" | head -20 || \
  git diff HEAD~1 -- nmap.cc 2>/dev/null | grep "^[+-]" | grep -v "^---\|^+++" | head -20 || \
  echo "  (diff unavailable in this context)"
echo
echo "  libnetutil/PacketElement.h — added #include <cstring>"
echo "  libnetutil/netutil.cc — fixed include ordering"
echo "  build-offline.sh — new file (CRLF fix + OpenSSL build + JDWP compile)"

echo
echo "--- Flawfinder on our diff only ---"
flawfinder --minlevel=1 \
  nmap.cc NmapOps.cc libnetutil/netutil.cc \
  2>/dev/null | grep -E "Level [1-5]:" | \
  grep -oE "([A-Za-z_]+)\s+\[.*\]" | sort | uniq -c | sort -rn | head -10

# =============================================================================
P "7. SUMMARY TABLE"
# =============================================================================
CPPCHECK_ERR=$(grep -c "\[error\]" "$REPORT_DIR/cppcheck-nmap.txt" 2>/dev/null || echo 0)
CPPCHECK_WARN=$(grep -c "\[warning\]" "$REPORT_DIR/cppcheck-nmap.txt" 2>/dev/null || echo 0)
FLAWFINDER_L3=$(grep -c "Level [3-5]:" "$REPORT_DIR/flawfinder-core.txt" 2>/dev/null || echo 0)
SEMGREP_TOTAL=$(python3 -c "import json; d=json.load(open('$REPORT_DIR/semgrep-c.json')); print(len(d.get('results',[])))" 2>/dev/null || echo "n/a")
SHELLCHECK_WARN=$(grep -c "^In\|warning:" "$REPORT_DIR/shellcheck-build.txt" 2>/dev/null || echo 0)

echo
printf "  %-30s %-12s %-12s %-12s\n" "Tool" "Critical/Error" "Warning" "Info/Style"
printf "  %-30s %-12s %-12s %-12s\n" "------------------------------" "------------" "------------" "------------"
printf "  %-30s %-12s %-12s %-12s\n" "Cppcheck (nmap core)"     "$CPPCHECK_ERR"  "$CPPCHECK_WARN" "-"
printf "  %-30s %-12s %-12s %-12s\n" "Flawfinder (core, L3+)"   "$FLAWFINDER_L3" "-"             "-"
printf "  %-30s %-12s %-12s %-12s\n" "Semgrep C/C++"            "-"              "$SEMGREP_TOTAL" "-"
printf "  %-30s %-12s %-12s %-12s\n" "ShellCheck (build.sh)"    "-"              "$SHELLCHECK_WARN" "-"
printf "  %-30s %-12s %-12s %-12s\n" "Cppcheck OpenSSL (ref)"   "$OSSL_ERRORS"   "-"             "-"
echo
echo "Raw report files saved to: $REPORT_DIR/"
ls "$REPORT_DIR/"
echo
echo "=== SAST ANALYSIS COMPLETE ==="
