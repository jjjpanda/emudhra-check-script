#!/usr/bin/env bash
# eMudhra compromised-intermediate exposure check for macOS.
# Ref: https://emudhra.we-have-a-problem.com/
#
# Usage:   bash check-mac.sh
# Method:  1) compare installed versions against the patched-version table
#          2) live TLS test: each client connects to the 12 advisory test hosts
#             (6 compromised TLS intermediates x 2 roots: emSign Root TLS G3 and the
#             Sectigo "AAA Certificate Services" cross-sign) plus a control host.
#             A patched client must REJECT all 12.
# Codes:   13 letters per client = 12 test hosts (order of TEST_HOSTS), then control (example.com)
#          S = TLS accepted   C = rejected as untrusted/revoked   N = network/other error
#          any S in the first 12 = FAIL;  CCCCCCCCCCCC + S = OK;  anything else = NOT VERIFIED
# Output:  [OK] / [INFO] / [WARN] / [FAIL] lines, then a SUMMARY with remediation steps.
# Exit:    0 = no issues, 1 = issues found, 2 = no issues but some checks not verified
# Note:    /usr/bin/python3, pip3 and git are skipped if Xcode Command Line Tools are
#          missing (running them would open an install dialog).

REF=https://emudhra.we-have-a-problem.com/
TEST_HOSTS="dv-g3b dv-g3b-aaa dv-g3c dv-g3c-aaa ov-g3b ov-g3b-aaa ov-g3c ov-g3c-aaa ev-g3b ev-g3b-aaa ev-g3c ev-g3c-aaa"
URLS="$(for h in $TEST_HOSTS; do printf 'https://%s-emudhra.we-have-a-problem.com/ ' "$h"; done)https://example.com/"
NT=$(set -- $TEST_HOSTS; echo $#)
ALL_C=$(printf 'C%.0s' $TEST_HOSTS)
ISSUES=()
UNTESTED=()
SEEN_BUNDLES='|'
PYB=
CLT=0; xcode-select -p >/dev/null 2>&1 && CLT=1
OSFIX="install latest macOS updates (System Settings > General > Software Update)"
CERTPEM_FIX="back up /etc/ssl/cert.pem, remove 'AAA Certificate Services' and 'emSign ECC Root CA - G3' from it (see $REF)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

ok()     { printf '[OK]   %s\n' "$*"; }
info()   { printf '[INFO] %s\n' "$*"; }
fail()   { printf '[FAIL] %s\n' "$1"; ISSUES+=("$1 -> $2"); }
warn()   { printf '[WARN] %s\n' "$1"; if [ -n "${2:-}" ]; then ISSUES+=("$1 -> $2"); else UNTESTED+=("$1"); fi; }
hdr()    { printf '\n== %s ==\n' "$*"; }
have()   { command -v "$1" >/dev/null 2>&1; }
ver()    { grep -Eo '[0-9]+(\.[0-9]+)+' | head -1; }
kv()     { printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -1; }
rp()     { realpath "$1" 2>/dev/null || readlink -f "$1" 2>/dev/null || printf '%s\n' "$1"; }
redact() { printf '%s' "$1" | sed -E 's#//[^/@]*@#//***@#'; }

# to SECONDS CMD...: run CMD with a hard deadline (macOS has no timeout(1) by default; perl alarm is the fallback)
to() {
  if have timeout; then timeout "$@"
  elif have gtimeout; then gtimeout "$@"
  else perl -e 'alarm shift; exec @ARGV or exit 127' "$@"
  fi
}

# vge A B: true if version A >= version B (numeric fields, any separators)
vge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    sub(/^[^0-9]+/, "", a); sub(/^[^0-9]+/, "", b)
    n = split(a, x, /[^0-9]+/); m = split(b, y, /[^0-9]+/)
    for (i = 1; i <= (n > m ? n : m); i++) { if (x[i]+0 > y[i]+0) exit 0; if (x[i]+0 < y[i]+0) exit 1 }
    exit 0 }'
}

# branch V N: first N numeric fields of V (e.g. branch 22.1.0 1 -> 22)
branch() { printf '%s\n' "$1" | sed 's/^[^0-9]*//' | tr -c '0-9\n' '.' | cut -d. -f1-"$2"; }

# need LABEL VERSION BRANCH_DEPTH FIX PATCHED...: OK if VERSION >= patch of its branch, or >= all patches
need() {
  local label=$1 v=$2 depth=$3 fix=$4 p all=1; shift 4
  local want; want=$(printf '%s | ' "$@" | sed 's/ | $//')
  case $v in *-rc*|*-beta*|*-alpha*|*-pre*|*-ea*|*-nightly*|*-canary*) fail "$label $v (pre-release)" "$fix to a stable release (>= $want)"; return ;; esac
  for p in "$@"; do
    vge "$v" "$p" || { all=0; continue; }
    [ "$(branch "$v" "$depth")" = "$(branch "$p" "$depth")" ] && { ok "$label $v"; return; }
  done
  [ $all = 1 ] && ok "$label $v" || fail "$label $v" "$fix (>= $want)"
}

# one NAME MIN FIX CMD...: single minimum version check for a tool on PATH
one() {
  local name=$1 min=$2 fix=$3 v; shift 3
  have "$1" || return
  v=$(to 30 "$@" 2>/dev/null </dev/null | ver)
  [ -z "$v" ] && { warn "$name: version unknown"; return; }
  vge "$v" "$min" && ok "$name $v" || fail "$name $v" "$fix (>= $min)"
}

# res LABEL CODES FIX: CODES = one letter per test host, then the control host
res() {
  local tests=${2%?} ctrl=${2#"${2%?}"} n
  n=$(printf '%s' "$tests" | tr -cd S | wc -c | tr -d ' ')
  if [ "$n" -gt 0 ]; then fail "$1: TRUSTS $n/$NT compromised chains [$2]" "$3"
  elif [ "$tests" = "$ALL_C" ] && [ "$ctrl" = S ]; then ok "$1: rejects all $NT compromised chains"
  else warn "$1: not verified [${2:-no output}]"
  fi
}

# rejected MSG: true only for untrusted-issuer / revoked errors (not generic TLS or network errors)
rejected() {
  case $1 in
    *"local issuer"*|*"issuer certificate"*|*"self-signed certificate in"*|*"self signed certificate in"*|\
    *"locally verify"*|*"unable to verify the first"*|*revoked*|*REVOKED*|*UNTRUSTED*|*"not trusted"*) return 0 ;;
  esac
  return 1
}

# probe LABEL OUTPUT FIX: report an in-container test (lines: codes, ca-certificates version, client used)
probe() {
  local codes pkg via
  codes=$(printf '%s\n' "$2" | sed -n 1p); pkg=$(printf '%s\n' "$2" | sed -n 2p); via=$(printf '%s\n' "$2" | sed -n 3p)
  case $codes in
    '')  warn "$1: cannot run sh (distroless/other arch/timeout)" ;;
    *X*) warn "$1: no curl/wget/python3 inside; ca-certificates ${pkg:-?}" ;;
    *)   res "$1 via $via [ca-certificates ${pkg:-?}]" "$codes" "$3" ;;
  esac
}

# cands [--keep-links] NAME|PATH...: unique executables from PATH names and explicit paths/globs
cands() {
  local a p r seen='|' links=0
  [ "$1" = --keep-links ] && { links=1; shift; }
  for a in "$@"; do
    case $a in */*) printf '%s\n' "$a" ;; *) type -aP "$a" 2>/dev/null ;; esac
  done | while IFS= read -r p; do
    [ -f "$p" ] && [ -x "$p" ] || continue
    case $p in */shims/*|*-config) continue ;; esac
    case $p in /usr/bin/python3|/usr/bin/pip3|/usr/bin/git) [ $CLT = 1 ] || continue ;; esac
    if [ $links = 1 ]; then r=$p; else r=$(rp "$p"); fi
    case $seen in *"|$r|"*) continue ;; esac
    seen="$seen$r|"; printf '%s\n' "$p"
  done
}

curl_codes() {
  local exe=$1 u e; shift
  for u in $URLS; do
    e=$(to 20 "$exe" "$@" -sS -o /dev/null -m 15 "$u" 2>&1 </dev/null) && { printf S; continue; }
    rejected "$e" && printf C || printf N
  done
}

git_codes() {
  local u e
  for u in $URLS; do
    e=$(GIT_TERMINAL_PROMPT=0 to 30 "$1" -c credential.helper= ls-remote "$u" 2>&1 </dev/null) && { printf S; continue; }
    if rejected "$e"; then printf C
    else
      case $e in
        *"not found"*|*"not valid"*|*"returned error"*|*Authentication*|*Username*|*repository*) printf S ;;
        *) printf N ;;
      esac
    fi
  done
}

# openssl verify codes 2/19/20/21/23/28 = issuer unknown/untrusted, self-signed in chain, revoked, rejected
openssl_codes() {
  local u h c
  for u in $URLS; do
    h=${u#https://}; h=${h%/}
    c=$(to 20 "$1" s_client -connect "$h:443" -servername "$h" </dev/null 2>&1 | sed -n 's/.*Verify return code: \([0-9]*\).*/\1/p' | tail -1)
    case $c in 0) printf S ;; 2|19|20|21|23|28) printf C ;; *) printf N ;; esac
  done
}

# macOS system trust (Security framework, as used by Safari / URLSession apps)
# NSURLError -1202 untrusted, -1203 unknown root, -1205 rejected = C; others = N
nsurl_codes() {
  to 300 osascript -l JavaScript -e '
    ObjC.import("Foundation");
    function run(argv) {
      return argv.map(function (u) {
        var e = Ref();
        var d = $.NSData.dataWithContentsOfURLOptionsError($.NSURL.URLWithString(u), 0, e);
        if (!d.isNil()) return "S";
        var c = e[0].code;
        return (c == -1202 || c == -1203 || c == -1205) ? "C" : "N";
      }).join("");
    }' $URLS 2>/dev/null </dev/null
}

# bundle LABEL FILE FIX: live-test one PEM CA bundle file (once per real path)
bundle() {
  local r
  [ -s "$2" ] || return
  r=$(rp "$2")
  case $SEEN_BUNDLES in *"|$r|"*) return ;; esac
  SEEN_BUNDLES="$SEEN_BUNDLES$r|"
  if [ -n "$PYB" ]; then
    res "$1 ($2)" "$(to 300 "$PYB" "$T/probe.py" --cafile "$2" $URLS 2>/dev/null </dev/null)" "$3"
  elif [ -n "$CURL1" ]; then
    res "$1 ($2)" "$(curl_codes "$CURL1" --cacert "$2")" "$3"
  else
    warn "$1 ($2): no python3/curl to test bundle"
  fi
}

cat > "$T/probe.py" <<'EOF'
import sys, ssl
try:
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    print("ver=" + sys.version.split()[0]); sys.exit()
VerifyError = getattr(ssl, "SSLCertVerificationError", None)
REJECT = (2, 19, 20, 21, 23, 28)  # issuer unknown/untrusted, self-signed in chain, revoked, rejected
def codes(urls, cafile=None):
    out = ""
    for u in urls:
        try:
            urlopen(u, timeout=15, context=ssl.create_default_context(cafile=cafile)); out += "S"
        except HTTPError:
            out += "S"
        except Exception as e:
            r = getattr(e, "reason", e)
            if VerifyError and isinstance(r, VerifyError):
                out += "C" if r.verify_code in REJECT else "N"
            else:
                out += "C" if "CERTIFICATE_VERIFY_FAILED" in str(r) else "N"
    return out
args = sys.argv[1:]
if args[:1] == ["--cafile"]:
    print(codes(args[2:], args[1])); sys.exit()
print("ver=" + sys.version.split()[0])
print("sys=" + codes(args))
for key, mod in (("certifi", "certifi"), ("pipcertifi", "pip._vendor.certifi")):
    try:
        m = __import__(mod, fromlist=["where"])
        print("%s=%s|%s|%s" % (key, getattr(m, "__version__", "?"), m.where(), codes(args, m.where())))
    except Exception:
        pass
try:
    import pip; print("pip=" + pip.__version__)
except Exception:
    pass
EOF

cat > "$T/probe.js" <<'EOF'
const https = require('https');
const REJECT = /^(UNABLE_TO_GET_ISSUER_CERT(_LOCALLY)?|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT_REVOKED|CERT_REJECTED|CERT_UNTRUSTED)$/;
const urls = process.argv.slice(2), out = urls.map(() => 'N');
let left = urls.length;
urls.forEach((u, i) => {
  let done = false;
  const fin = c => { if (done) return; done = true; out[i] = c; if (--left === 0) { console.log(out.join('')); process.exit(0); } };
  const req = https.get(u, { timeout: 15000 }, r => { r.resume(); fin('S'); });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => fin(REJECT.test(e.code) ? 'C' : 'N'));
});
EOF

# Runs inside each docker image/container with: sh -c "$IMG_SH" sh URL...
# Prints 3 lines: codes, ca-certificates version, client used (first of curl, wget, python3)
read -r -d '' IMG_SH <<'EOF'
r(){ case $* in *'local issuer'*|*'issuer certificate'*|*'self-signed certificate in'*|*'self signed certificate in'*|*'locally verify'*|*'unable to verify the first'*|*revoked*|*REVOKED*|*UNTRUSTED*|*'not trusted'*) printf C;; *) printf N;; esac; }; t(){ if command -v curl >/dev/null 2>&1; then T=curl; e=$(curl -sS -o /dev/null -m 15 $1 2>&1) && printf S || r $e; elif command -v wget >/dev/null 2>&1; then T=wget; e=$(wget -q -T 15 -O /dev/null $1 2>&1); c=$?; if [ $c = 0 ] || [ $c = 8 ]; then printf S; else r $e; fi; elif command -v python3 >/dev/null 2>&1; then T=python3; e=$(python3 -c 'import sys,urllib.request as u;u.urlopen(sys.argv[1],timeout=15)' $1 2>&1); c=$?; if [ $c = 0 ] || echo $e | grep -q HTTPError; then printf S; else r $e; fi; else T=none; printf X; fi; }; for u; do t $u; done; echo; echo $( (dpkg-query -W -f='${Version}' ca-certificates || apk info -v ca-certificates || rpm -q ca-certificates) 2>/dev/null | head -1); echo $T
EOF

echo "eMudhra CA exposure check (macOS) - ref: $REF"
echo "Codes: $NT test hosts ($TEST_HOSTS) + control; S=TLS accepted, C=rejected untrusted/revoked, N=other error"

hdr "macOS"
info "macOS $(sw_vers -productVersion) build $(sw_vers -buildVersion) ($(uname -m))"
[ $CLT = 1 ] && info "Xcode CLT: $(xcode-select -p)" || info "Xcode CLT not installed; /usr/bin python3/pip3/git skipped"
res "macOS system trust (Safari/URLSession)" "$(nsurl_codes)" "$OSFIX"

hdr "Tools for bundle tests"
for py in $(cands python3 python); do "$py" -c 'import ssl; ssl.create_default_context' 2>/dev/null </dev/null && { PYB=$py; break; }; done
CURL1=$(cands curl | head -1)
info "bundle tester: ${PYB:-${CURL1:-none}}"

hdr "CA bundles"
bundle "/etc/ssl/cert.pem (system curl/git/python3/perl/ruby/openssl)" /etc/ssl/cert.pem "$CERTPEM_FIX"
if have brew; then
  BP=$(brew --prefix)
  cv=$(brew list --versions ca-certificates 2>/dev/null | awk '{print $2}')
  [ -n "$cv" ] && { vge "$cv" 2026-09-25_1 && ok "brew ca-certificates $cv" || fail "brew ca-certificates $cv" "brew update && brew upgrade ca-certificates (>= 2026-09-25_1)"; }
  for f in "$BP"/etc/ca-certificates/cert.pem "$BP"/etc/openssl@3/cert.pem "$BP"/etc/openssl@1.1/cert.pem "$BP"/etc/openssl/cert.pem; do
    bundle "Homebrew bundle" "$f" "brew update && brew upgrade ca-certificates"
  done
fi
for f in /opt/local/share/curl/curl-ca-bundle.crt /opt/local/etc/openssl/cert.pem; do
  bundle "MacPorts bundle" "$f" "sudo port selfupdate && sudo port upgrade curl-ca-bundle"
done
[ -d /nix ] && info "Nix present: nix-darwin users also follow the NixOS steps at $REF"

hdr "curl"
while IFS= read -r c <&3; do
  info "$("$c" --version 2>/dev/null </dev/null | head -1) ($c)"
  case $c in /usr/bin/*) f=$CERTPEM_FIX ;; *) f="update this curl / its CA bundle (brew upgrade curl ca-certificates)" ;; esac
  res "curl ($c)" "$(curl_codes "$c")" "$f"
done 3< <(cands curl /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl /opt/local/bin/curl)

hdr "git"
while IFS= read -r g <&3; do
  info "$("$g" --version 2>/dev/null </dev/null) ($g)"
  case $g in /usr/bin/*|/Library/Developer/*|/Applications/Xcode*) f=$CERTPEM_FIX ;; *) f="brew upgrade git ca-certificates; check http.sslCAInfo" ;; esac
  res "git ls-remote ($g)" "$(git_codes "$g")" "$f"
done 3< <(cands git /opt/homebrew/bin/git /usr/local/bin/git)

hdr "openssl"
while IFS= read -r o <&3; do
  info "$("$o" version 2>/dev/null </dev/null) ($o)"
  case $o in /usr/bin/*) f=$CERTPEM_FIX ;; *) f="brew upgrade ca-certificates openssl@3" ;; esac
  res "openssl s_client ($o)" "$(openssl_codes "$o")" "$f"
done 3< <(cands openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl)

hdr "Python / pip / certifi"
PY_SEEN='|'
while IFS= read -r py <&3; do
  prefix=$(to 30 "$py" -c 'import os,sys;print(os.path.realpath(sys.prefix))' 2>/dev/null </dev/null)
  [ -z "$prefix" ] && { warn "python ($py): did not run"; continue; }
  case $PY_SEEN in *"|$prefix|"*) continue ;; esac
  PY_SEEN="$PY_SEEN$prefix|"
  out=$(to 600 "$py" "$T/probe.py" $URLS 2>/dev/null </dev/null)
  v=$(kv ver "$out")
  [ -z "$(kv sys "$out")" ] && { warn "python ${v:-?} ($py): too old to test or probe failed"; continue; }
  case $py in
    /usr/bin/*|/Library/Developer/*) pipfix="$CERTPEM_FIX; set PIP_CERT=/etc/ssl/cert.pem via sitecustomize.py (see $REF)" ;;
    *) pipfix="$py -m pip install -U pip certifi" ;;
  esac
  case $py in
    /Library/Frameworks/*) sysfix="run '/Applications/Python ${v%.*}/Install Certificates.command' after certifi update" ;;
    /usr/bin/*|/Library/Developer/*) sysfix=$CERTPEM_FIX ;;
    *) sysfix="brew upgrade ca-certificates; or set SSL_CERT_FILE to a patched bundle" ;;
  esac
  res "python $v ($py) default trust" "$(kv sys "$out")" "$sysfix"
  c=$(kv certifi "$out")
  if [ -n "$c" ]; then
    cv=${c%%|*}; rest=${c#*|}; cp=${rest%|*}
    vge "$cv" 2026.10.19 && ok "certifi $cv ($cp)" || fail "certifi $cv ($cp)" "$pipfix (certifi >= 2026.10.19)"
    res "certifi bundle ($cp)" "${rest##*|}" "$pipfix"
    SEEN_BUNDLES="$SEEN_BUNDLES$(rp "$cp")|"
  fi
  pv=$(kv pip "$out")
  [ -n "$pv" ] && { vge "$pv" 26.2.2 && ok "pip $pv ($py)" || fail "pip $pv ($py)" "$pipfix (pip >= 26.2.2)"; }
  c=$(kv pipcertifi "$out")
  [ -n "$c" ] && { rest=${c#*|}; res "pip vendored certifi ${c%%|*}" "${rest##*|}" "$pipfix"; }
done 3< <(cands --keep-links python python3 python2 python3.8 python3.9 python3.10 python3.11 python3.12 python3.13 python3.14 \
  /usr/bin/python3 /opt/homebrew/bin/python3* /usr/local/bin/python3* /opt/homebrew/opt/python@*/bin/python3 \
  /Library/Frameworks/Python.framework/Versions/*/bin/python3 /opt/local/bin/python3* \
  ~/.pyenv/versions/*/bin/python3 ~/.local/share/uv/python/*/bin/python3 \
  ~/.asdf/installs/python/*/bin/python3 ~/.local/share/mise/installs/python/*/bin/python3 \
  ~/miniconda3/bin/python ~/anaconda3/bin/python ~/miniforge3/bin/python ~/mambaforge/bin/python \
  /opt/miniconda3/bin/python /opt/anaconda3/bin/python /opt/homebrew/Caskroom/miniforge/base/bin/python \
  ~/miniconda3/envs/*/bin/python ~/anaconda3/envs/*/bin/python ~/miniforge3/envs/*/bin/python /opt/miniconda3/envs/*/bin/python)

hdr "Node.js / npm"
while IFS= read -r n <&3; do
  v=$("$n" -v 2>/dev/null </dev/null) || continue
  need "node ($n)" "$v" 1 "upgrade Node.js" 22.23.4 24.22.1 26.12.1
  res "node $v ($n)" "$(to 120 "$n" "$T/probe.js" $URLS 2>/dev/null </dev/null)" "upgrade Node.js to a patched release"
  [ -x "$(dirname "$n")/npm" ] && info "npm $("$(dirname "$n")/npm" -v 2>/dev/null </dev/null) ($(dirname "$n")/npm)"
done 3< <(cands node ~/.nvm/versions/node/*/bin/node ~/.volta/tools/image/node/*/bin/node \
  ~/.local/share/fnm/node-versions/*/installation/bin/node "$HOME/Library/Application Support/fnm/node-versions"/*/installation/bin/node \
  /usr/local/n/versions/node/*/bin/node ~/.asdf/installs/nodejs/*/bin/node ~/.local/share/mise/installs/node/*/bin/node \
  /opt/homebrew/opt/node*/bin/node /usr/local/opt/node*/bin/node)

hdr "Java"
while IFS= read -r j <&3; do
  jv=$(to 30 "$j" -version 2>&1 </dev/null | head -1 | sed -E 's/.*version "([^"]+)".*/\1/')
  case $jv in 1.*) jv=${jv#1.}; jv=${jv/_/.} ;; esac
  need "java ($j)" "$jv" 1 "upgrade JDK" 27.0.1.0.2 25.0.5.0.2 21.0.13.0.2 17.0.21.0.2 11.0.33.0.2 8.0.511
done 3< <(cands ${JAVA_HOME:+"$JAVA_HOME/bin/java"} /Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java \
  ~/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java /opt/homebrew/opt/openjdk*/bin/java /usr/local/opt/openjdk*/bin/java \
  ~/.sdkman/candidates/java/*/bin/java)

hdr "Go"
while IFS= read -r g <&3; do
  need "go ($g)" "$("$g" version 2>/dev/null </dev/null | ver)" 2 "upgrade Go" 1.27.3 1.26.10
done 3< <(cands go /usr/local/go/bin/go ~/sdk/go*/bin/go /opt/homebrew/opt/go*/bin/go ~/.local/share/mise/installs/go/*/bin/go)

hdr "Other tools"
one uv 0.13.4 "uv self update" uv --version
one pixi 0.82.1 "pixi self-update" pixi --version
one rustup 1.29.2 "rustup self update" rustup --version
one deno 2.9.8 "deno upgrade" deno --version
one mise 2026.10.17 "mise self-update" mise --version
one "claude code" 2.1.303 "claude update" claude --version
have electron && need electron "$(to 30 electron --version 2>/dev/null </dev/null)" 1 "upgrade Electron" 44.9.1 43.8.1 42.11.16
have bun && warn "bun $(bun --version 2>/dev/null): vendor fix pending" "watch $REF; avoid bun for TLS to untrusted hosts"
pv=$(perl -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>/dev/null) && \
  { vge "$pv" 20261020 && ok "perl Mozilla::CA $pv" || fail "perl Mozilla::CA $pv" "cpan Mozilla::CA (>= 20261020)"; }

hdr "Env / config"
for e in SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE PIP_CERT NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO HTTPS_PROXY https_proxy; do
  [ -n "${!e:-}" ] && info "$e=$(redact "${!e}")"
done
for e in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE PIP_CERT NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO; do
  [ -n "${!e:-}" ] && bundle "\$$e" "${!e}" "replace $e file with a patched bundle"
done
[ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" = 0 ] && fail "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verify" "unset NODE_TLS_REJECT_UNAUTHORIZED"
[ "${PYTHONHTTPSVERIFY:-}" = 0 ] && fail "PYTHONHTTPSVERIFY=0 disables TLS verify" "unset PYTHONHTTPSVERIFY"
[ -n "${GIT_SSL_NO_VERIFY:-}" ] && fail "GIT_SSL_NO_VERIFY set" "unset GIT_SSL_NO_VERIFY"
grep -Eqs '^[[:space:]]*(-k|--insecure|insecure)' ~/.curlrc && fail "~/.curlrc disables TLS verify" "remove insecure/-k from ~/.curlrc"
GIT1=$(cands git /opt/homebrew/bin/git /usr/local/bin/git | head -1)
if [ -n "$GIT1" ]; then
  [ "$("$GIT1" config --get http.sslVerify)" = false ] && fail "git http.sslVerify=false" "git config --global --unset http.sslVerify"
  c=$("$GIT1" config --get http.sslCAInfo) && bundle "git http.sslCAInfo" "$c" "point http.sslCAInfo to a patched bundle"
fi
if have npm; then
  [ "$(to 30 npm config get strict-ssl 2>/dev/null)" = false ] && fail "npm strict-ssl=false" "npm config set strict-ssl true"
  c=$(to 30 npm config get cafile 2>/dev/null); [ -n "$c" ] && [ "$c" != null ] && [ "$c" != undefined ] && bundle "npm cafile" "$c" "update npm cafile bundle"
fi
if [ -n "$PYB" ]; then
  pc=$(to 30 "$PYB" -m pip config list 2>/dev/null </dev/null)
  c=$(printf '%s\n' "$pc" | sed -n "s/^[a-z]*\.cert='\(.*\)'$/\1/p" | head -1); [ -n "$c" ] && bundle "pip config cert" "$c" "update pip cert bundle"
  printf '%s\n' "$pc" | grep -q trusted-host && warn "pip trusted-host set (TLS verify off for those hosts)" "remove trusted-host from pip config"
fi

hdr "Browsers"
for app in Safari "Google Chrome" "Microsoft Edge" Firefox "Brave Browser" Arc Chromium Opera Vivaldi; do
  for d in /Applications ~/Applications; do
    [ -f "$d/$app.app/Contents/Info.plist" ] && info "$app $(defaults read "$d/$app.app/Contents/Info" CFBundleShortVersionString 2>/dev/null)"
  done
done

hdr "Docker"
[ -f /Applications/Docker.app/Contents/Info.plist ] && \
  info "Docker Desktop $(defaults read /Applications/Docker.app/Contents/Info CFBundleShortVersionString 2>/dev/null): no patched version listed; keep it updated"
if ! have docker; then
  info "docker not installed"
elif ! sv=$(to 15 docker version --format '{{.Server.Version}}' 2>/dev/null </dev/null) || [ -z "$sv" ]; then
  warn "docker daemon not reachable; images/containers not checked (start Docker Desktop, re-run)"
else
  info "docker client $(docker version --format '{{.Client.Version}}' 2>/dev/null), server $sv"
  while IFS= read -r img <&3; do
    probe "image $img" "$(to 300 docker run --rm --pull=never --entrypoint sh "$img" -c "$IMG_SH" sh $URLS 2>/dev/null </dev/null)" \
      "rebuild/pull $img with updated ca-certificates"
  done 3< <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u)
  while IFS='|' read -r name img <&3; do
    probe "running container $name ($img)" "$(to 300 docker exec "$name" sh -c "$IMG_SH" sh $URLS 2>/dev/null </dev/null)" \
      "rebuild $img with updated ca-certificates, then redeploy $name"
  done 3< <(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null)
fi

hdr "SUMMARY"
[ ${#ISSUES[@]} -eq 0 ] && [ ${#UNTESTED[@]} -eq 0 ] && echo "No issues found; all checks verified."
if [ ${#ISSUES[@]} -gt 0 ]; then
  echo "${#ISSUES[@]} issue(s) to fix:"
  for i in "${ISSUES[@]}"; do printf ' - %s\n' "$i"; done
fi
if [ ${#UNTESTED[@]} -gt 0 ]; then
  echo "${#UNTESTED[@]} check(s) NOT verified (fix network/tooling and re-run, or check by hand):"
  for i in "${UNTESTED[@]}"; do printf ' - %s\n' "$i"; done
fi
echo "Manual: in each browser open https://<host>-emudhra.we-have-a-problem.com/ for each host: $TEST_HOSTS. Each must show a certificate error."
echo "Scope: images/containers test only the first client found (curl > wget > python3). Not scanned: project deps (rustls-webpki, webpki-roots, castore, composer/ca-bundle), Electron apps."
[ ${#ISSUES[@]} -gt 0 ] && exit 1
[ ${#UNTESTED[@]} -gt 0 ] && exit 2
exit 0
