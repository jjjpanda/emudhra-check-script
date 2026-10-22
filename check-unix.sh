#!/usr/bin/env bash
# eMudhra compromised-intermediate exposure check for Linux (also WSL distros) and macOS.
# Ref: https://emudhra.we-have-a-problem.com/
#
# Usage:   bash check-unix.sh [--no-docker] [--fix]
# Method:  1) compare installed versions against the patched-version table
#          2) live TLS test: each client connects to the 12 advisory test hosts
#             (6 compromised TLS intermediates x 2 roots: emSign Root TLS G3 and the
#             Sectigo "AAA Certificate Services" cross-sign) plus a control host.
#             A patched client must REJECT all 12.
#          Browsers are not driven; the SUMMARY gives a manual test.
#          macOS: Safari has no headless mode; the system trust test covers its trust store.
# Codes:   13 letters per client = 12 test hosts (order of TEST_HOSTS), then control (example.com)
#          S = TLS accepted   C = rejected as untrusted/revoked   N = network/other error
#          any S in the first 12 = FAIL;  CCCCCCCCCCCC + S = OK;  anything else = NOT VERIFIED
# Output:  [OK] / [INFO] / [WARN] / [FAIL] lines, then a SUMMARY: issues, fix commands, manual steps.
# --fix:   after the checks, run the fix commands (only package-manager / self-update
#          commands that are known to be correct for how each item was installed).
# Exit:    0 = no issues, 1 = issues found, 2 = no issues but some checks not verified;
#          with --fix: 3 = a fix command failed; else the codes above, from the scan before the fixes (re-run to verify)
# Note:    macOS: /usr/bin/python3, pip3 and git are skipped if Xcode Command Line Tools are
#          missing (running them would open an install dialog). Runs on the system bash 3.2.

case $(uname -s) in
  Linux)  OS=linux; OSNAME=Linux ;;
  Darwin) OS=mac; OSNAME=macOS ;;
  *)      echo "unsupported OS: $(uname -s) (use check-windows.ps1 on Windows)" >&2; exit 2 ;;
esac

REF=https://emudhra.we-have-a-problem.com/
TEST_HOSTS="dv-g3b dv-g3b-aaa dv-g3c dv-g3c-aaa ov-g3b ov-g3b-aaa ov-g3c ov-g3c-aaa ev-g3b ev-g3b-aaa ev-g3c ev-g3c-aaa"
URLS="$(for h in $TEST_HOSTS; do printf 'https://%s-emudhra.we-have-a-problem.com/ ' "$h"; done)https://example.com/"
NT=$(set -- $TEST_HOSTS; echo $#)
ALL_C=$(printf 'C%.0s' $TEST_HOSTS)
NO_DOCKER=0; FIX=0; FIXFAIL=0
for a; do case $a in --no-docker) NO_DOCKER=1 ;; --fix) FIX=1 ;; esac; done
ISSUES=()
UNTESTED=()
CMDS=()
STEPS=()
TOOLFIX=()
SEEN_BUNDLES='|'
PYB=
PKGUP=
SUDO=sudo; [ "$(id -u)" = 0 ] && SUDO=
CLT=1; [ $OS = mac ] && { xcode-select -p >/dev/null 2>&1 || CLT=0; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

ok()     { printf '[OK]   %s\n' "$*"; }
info()   { printf '[INFO] %s\n' "$*"; }
fail()   { printf '[FAIL] %s\n' "$1"; note "$@"; }
warn()   { printf '[WARN] %s\n' "$1"; if [ -n "${2:-}${3:-}" ]; then note "$@"; else UNTESTED+=("$1"); fi; }
q()      { printf '%q' "$1"; }
hdr()    { printf '\n== %s ==\n' "$*"; }
have()   { command -v "$1" >/dev/null 2>&1; }
ver()    { grep -Eo '[0-9]+(\.[0-9]+)+' | head -1; }
kv()     { printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -1; }
rp()     { realpath "$1" 2>/dev/null || readlink -f "$1" 2>/dev/null || perl -MCwd -e 'print Cwd::abs_path(shift), "\n"' "$1" 2>/dev/null || printf '%s\n' "$1"; }
redact() { printf '%s' "$1" | sed -E 's#//[^/@]*@#//***@#'; }

# note ISSUE STEP [CMD]: record an issue; CMD = command safe to run with --fix, else STEP is a manual step
note() {
  local i
  if [ -n "${3:-}" ]; then
    for i in "${!CMDS[@]}"; do [ "${CMDS[$i]}" = "$3" ] && break; i=; done
    [ -z "$i" ] && { CMDS+=("$3"); i=$((${#CMDS[@]} - 1)); }
    ISSUES+=("$1  -> cmd $((i + 1))")
  else
    for i in "${!STEPS[@]}"; do [ "${STEPS[$i]}" = "$2" ] && break; i=; done
    [ -z "$i" ] && { STEPS+=("$2"); i=$((${#STEPS[@]} - 1)); }
    ISSUES+=("$1  -> step $((i + 1))")
  fi
}

# summary: issues, fix commands, manual steps, unverified checks; with --fix, run the fix commands
summary() {
  local i
  hdr "SUMMARY"
  [ ${#ISSUES[@]} -eq 0 ] && [ ${#UNTESTED[@]} -eq 0 ] && echo "No issues found; all checks verified."
  if [ ${#ISSUES[@]} -gt 0 ]; then
    echo "Issues (${#ISSUES[@]}):"; printf '  - %s\n' "${ISSUES[@]}"
  fi
  if [ ${#CMDS[@]} -gt 0 ]; then
    echo; echo "Fix commands (run them, or re-run with --fix):"
    for i in "${!CMDS[@]}"; do printf '  cmd %d: %s\n' $((i + 1)) "${CMDS[$i]}"; done
  fi
  if [ ${#STEPS[@]} -gt 0 ]; then
    echo; echo "Manual steps:"
    for i in "${!STEPS[@]}"; do printf '  step %d: %s\n' $((i + 1)) "${STEPS[$i]}"; done
  fi
  if [ ${#UNTESTED[@]} -gt 0 ]; then
    echo; echo "Not verified (${#UNTESTED[@]}; fix network/tooling and re-run, or check by hand):"; printf '  - %s\n' "${UNTESTED[@]}"
  fi
  echo
  echo "If a fix command finds no newer package, distrust the roots by hand: $REF"
  echo "Browsers are not tested: open each URL below in each browser; all $NT must show a certificate error."
  for h in $TEST_HOSTS; do printf '  https://%s-emudhra.we-have-a-problem.com/\n' "$h"; done
  echo "Not scanned: project deps (rustls-webpki, webpki-roots, castore, composer/ca-bundle), Electron apps; images/containers test only their first client (curl > wget > python3)."
  [ $FIX = 1 ] && [ ${#CMDS[@]} -gt 0 ] || return 0
  hdr "FIX"
  for i in "${!CMDS[@]}"; do
    printf '\n+ cmd %d: %s\n' $((i + 1)) "${CMDS[$i]}"
    if eval "${CMDS[$i]}"; then ok "cmd $((i + 1))"; else printf '[FAIL] cmd %d (exit %d)\n' $((i + 1)) $?; FIXFAIL=1; fi
  done
  echo; echo "Re-run this script to verify the fixes."
}

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
  [ -z "$v" ] && { warn "$label: version unknown"; return; }
  local want; want=$(printf '%s | ' "$@" | sed 's/ | $//')
  case $v in *-rc*|*-beta*|*-alpha*|*-pre*|*-ea*|*-nightly*|*-canary*) fail "$label $v (pre-release)" "$fix to a stable release (>= $want)"; return ;; esac
  for p in "$@"; do
    vge "$v" "$p" || { all=0; continue; }
    [ "$(branch "$v" "$depth")" = "$(branch "$p" "$depth")" ] && { ok "$label $v"; return; }
  done
  [ $all = 1 ] && ok "$label $v" || fail "$label $v" "$fix (>= $want)"
}

# owner PATH: distro package that owns PATH (empty if none)
owner() {
  { dpkg -S "$1" 2>/dev/null | sed -n '1s/: .*//p'; rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v ' '; pacman -Qqo "$1" 2>/dev/null; } | head -1
}

# brewof PATH: the brew of the Homebrew prefix that owns PATH
brewof() {
  local p=${1%%/Cellar/*}; p=${p%%/Caskroom/*}
  case $p in /opt/homebrew/*) p=/opt/homebrew ;; */.linuxbrew/*) p=${p%%/.linuxbrew/*}/.linuxbrew ;; esac
  q "$p/bin/brew"
}

# jsfix PATH: upgrade command for a global JS package that contains PATH (npm of the same node, pnpm, bun, yarn)
jsfix() {
  local pkg pre
  pkg=${1#*/node_modules/}; case $pkg in .pnpm/*) pkg=${pkg##*/node_modules/} ;; esac
  pkg=$(printf '%s' "$pkg" | sed -E 's#^((@[^/]+/)?[^/]+).*#\1#')
  case $1 in
    */pnpm/*)                echo "pnpm add -g $pkg" ;;
    */.bun/install/global/*) echo "bun add -g $pkg" ;;
    */yarn/global/*)         echo "yarn global add $pkg" ;;
    */lib/node_modules/*) pre=${1%%/lib/node_modules/*}
       if [ -x "$pre/bin/node" ] && [ -e "$pre/bin/npm" ]; then echo "$(q "$pre/bin/node") $(q "$pre/bin/npm") install -g --prefix $(q "$pre") $pkg"
       else echo "npm install -g --prefix $(q "$pre") $pkg"; fi ;;
  esac
}

# upcmd PATH SELF: upgrade command for the copy of a tool at PATH, by how it was installed (empty = unsure)
upcmd() {
  local p=$1 n r e o
  n=$(basename "$p"); r=$(rp "$p")
  for e in "${TOOLFIX[@]}"; do [ "${e%%|*}" = "$r" ] && { printf '%s\n' "${e#*|}"; return; }; done
  case $p in
    /snap/*) echo "$SUDO snap refresh $n"; return ;;
    */.pixi/bin/*) [ "$n" = pixi ] || { echo "pixi global update $n"; return; } ;;
  esac
  case $r in
    */Cellar/*|*/Caskroom/*) echo "$(brewof "$r") upgrade $(printf '%s' "$r" | sed -E 's#.*/(Cellar|Caskroom)/([^/]+)/.*#\2#')" ;;
    */node_modules/*)        jsfix "$r" ;;
    */mise/installs/*)       echo "mise upgrade $(printf '%s' "$r" | sed -E 's#.*/mise/installs/([^/]+)/.*#\1#')" ;;
    /nix/*) ;;
    /usr/bin/*|/usr/lib/*|/usr/libexec/*|/usr/share/*|/bin/*) o=$(owner "$p"); [ -z "$o" ] && o=$(owner "$r")
                             [ -n "${PKGUP:-}" ] && [ -n "$o" ] && echo "$PKGUP $o" ;;
    */.cargo/bin/*)          { [ "$n" = rustup ] || [ -f "${XDG_CONFIG_HOME:-$HOME/.config}/$n/$n-receipt.json" ]; } && echo "$(q "$p") $2" ;;
    *) case $p in "$HOME"/.local/bin/*|"$HOME"/.deno/bin/*|"$HOME"/.pixi/bin/*) echo "$(q "$p") $2" ;; esac ;;
  esac
}

# tool NAME MIN SELF: version-check every copy of NAME (PATH and python envs); fix by install method
tool() {
  local name=$1 min=$2 self=$3 p v e extra=()
  for e in "${TOOLFIX[@]}"; do p=${e%%|*}; case $p in */"$name") extra+=("$p") ;; esac; done
  while IFS= read -r p <&4; do
    v=$(to 30 "$p" --version 2>/dev/null </dev/null | ver)
    [ -z "$v" ] && { warn "$name ($p): version unknown"; continue; }
    vge "$v" "$min" && { ok "$name $v ($p)"; continue; }
    fail "$name $v ($p) (need >= $min)" "upgrade $p with the tool that installed it" "$(upcmd "$p" "$self")"
  done 4< <(cands "$name" "${extra[@]}")
}

# pyfix PY PREFIX EM INSTALLER USER PKG...: command that upgrades PKGs in the env of PY (empty = OS-managed, fix by hand)
pyfix() {
  local py=$1 prefix=$2 em=$3 inst=$4 user=$5; shift 5
  case $prefix in
    */pipx/venvs/*)       echo "PIPX_HOME=$(q "${prefix%/venvs/*}") pipx runpip $(basename "$prefix") install -U $*"; return ;;
    */uv/tools/*)         echo "uv tool upgrade $(basename "$prefix")"; return ;;
    "$HOME"/.pixi/envs/*) echo "pixi global update $(basename "$prefix")"; return ;;
    /usr|/System/*|/Library/Developer/*) return ;;
  esac
  [ "$em" = 1 ] && return
  [ "$user" = 1 ] && { echo "$(q "$py") -m pip install --user -U $*"; return; }
  case $inst in
    conda) [ -n "$CONDA" ] && echo "$CONDA update -y -p $(q "$prefix") $*" ;;
    uv)    echo "uv pip install -p $(q "$py") -U $*" ;;
    *)     echo "$(q "$py") -m pip install -U $*" ;;
  esac
}

# res LABEL CODES STEP [CMD]: CODES = one letter per test host, then the control host
res() {
  local tests=${2%?} ctrl=${2#"${2%?}"} n
  n=$(printf '%s' "$tests" | tr -cd S | wc -c | tr -d ' ')
  if [ "$n" -gt 0 ]; then fail "$1: TRUSTS $n/$NT compromised chains [$2]" "$3" "${4:-}"
  elif [ "$tests" = "$ALL_C" ] && [ "$ctrl" = S ]; then ok "$1: rejects all $NT compromised chains"
  else warn "$1: not verified [${2:-no output}]"
  fi
}

# rejected MSG: true only for untrusted-issuer / revoked errors (not generic TLS or network errors)
rejected() {
  case $1 in
    *"local issuer"*|*"issuer certificate"*|*"self-signed certificate in"*|*"self signed certificate in"*|\
    *"locally verify"*|*"unable to verify the first"*|*revoked*|*REVOKED*|*UNTRUSTED*|*"not trusted"*|\
    *"server certificate verification failed"*) return 0 ;;
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
# NSURLError (read from NSUnderlyingError when wrapped in a Cocoa error) -1202 untrusted, -1203 unknown root = C; others = N
nsurl_codes() {
  to 300 osascript -l JavaScript -e '
    ObjC.import("Foundation");
    function run(argv) {
      return argv.map(function (u) {
        var e = Ref();
        var d = $.NSData.dataWithContentsOfURLOptionsError($.NSURL.URLWithString(u), 0, e);
        if (!d.isNil()) return "S";
        var ue = e[0].userInfo.objectForKey("NSUnderlyingError");
        var c = (ue && !ue.isNil()) ? ue.code : e[0].code;
        return (c == -1202 || c == -1203) ? "C" : "N";
      }).join("");
    }' $URLS 2>/dev/null </dev/null
}

# bundle LABEL FILE STEP [CMD]: live-test one PEM CA bundle file (once per real path)
bundle() {
  local r
  [ -s "$2" ] || return
  r=$(rp "$2")
  case $SEEN_BUNDLES in *"|$r|"*) return ;; esac
  SEEN_BUNDLES="$SEEN_BUNDLES$r|"
  if [ -n "$PYB" ]; then
    res "$1 ($2)" "$(to 300 "$PYB" "$T/probe.py" --cafile "$2" $URLS 2>/dev/null </dev/null)" "$3" "${4:-}"
  elif [ -n "$CURL1" ]; then
    res "$1 ($2)" "$(curl_codes "$CURL1" --cacert "$2")" "$3" "${4:-}"
  else
    warn "$1 ($2): no python3/curl to test bundle"
  fi
}

PY_NAMES=(python python3 python3.8 python3.9 python3.10 python3.11 python3.12 python3.13 python3.14)

# Platform parts: os_store, os_bundles, browsers, by, bfix, py_steps, py_trust and the *_CANDS search lists.
# by PATH: set FS (manual step) / FC (command) that fix the CA store used by the program at PATH
# bfix BUNDLE KIND: set BS (manual step) / BC (command) that fix the package that ships BUNDLE
#   (KIND = certifi|pip; uses py, prefix, em, ps, pc)
# py_steps: set ps / pc, the default fix for pip and certifi in the env at prefix
# py_trust: set FS / FC that fix the default trust of the python at py
if [ $OS = linux ]; then
  os_store() {
    hdr "OS CA store"
    [ -r /etc/os-release ] && . /etc/os-release
    ID=${ID:-unknown}
    info "${PRETTY_NAME:-$ID} ($(uname -r))"
    grep -qi microsoft /proc/version 2>/dev/null && info "running in WSL"
    CAPKG=ca-certificates
    case " $ID ${ID_LIKE:-} " in
      *" ubuntu "*|*" debian "*|*" devuan "*) PKGUP="$SUDO apt-get update && $SUDO apt-get install --only-upgrade -y" ;;
      *" alpine "*)                          PKGUP="$SUDO apk upgrade -U" ;;
      *" fedora "*|*" rhel "*|*" centos "*)  PKGUP="$SUDO dnf upgrade -y --refresh" ;;
      *" arch "*)                            PKGUP="$SUDO pacman -Syu --needed"; CAPKG=ca-certificates-mozilla ;;
      *" suse "*|*" opensuse "*)             PKGUP="$SUDO zypper -n up"; CAPKG=ca-certificates-mozilla ;;
      *" gentoo "*)                          PKGUP="$SUDO emerge -u"; CAPKG=app-misc/ca-certificates ;;
    esac
    CACMD=${PKGUP:+$PKGUP $CAPKG}
    CAFIX="distrust the emSign and AAA roots in the system CA store per $REF"
    [ "$ID" = nixos ] && CAFIX="add both roots to security.pki.caCertificateBlacklist per $REF"
  }
  os_bundles() {
    hdr "System CA bundles"
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
      bundle "system bundle" "$f" "$CAFIX" "$CACMD"
    done
  }
  browsers() {
    for b in google-chrome chromium chromium-browser microsoft-edge brave-browser vivaldi opera firefox firefox-esr; do
      have "$b" && info "$b $(to 30 "$b" --version 2>/dev/null </dev/null | ver)"
    done
  }
  by() {
    local r b; r=$(rp "$1"); b=$(brewof "$r")
    case $r in
      */Cellar/*|*/.linuxbrew/*) FS=; FC="$b update && $b upgrade ca-certificates" ;;
      /usr/*|/bin/*|/etc/*)    FS=$CAFIX; FC=$CACMD ;;
      *)                       FS="update $1 or point it to a patched CA bundle"; FC= ;;
    esac
  }
  bfix() {
    local o
    BS=$ps; BC=$pc
    case $1 in
      /etc/*)      BS=$CAFIX; BC=$CACMD; return ;;
      "$prefix"/*) [ "$prefix" = /usr ] || return ;;
      "$HOME"/*)   BS="upgrade the user-site package that ships $1"; BC=$([ "$em" = 1 ] || echo "$(q "$py") -m pip install --user -U pip certifi"); return ;;
    esac
    [ "$prefix" = /usr ] || return
    o=$(owner "$(rp "$1")")
    if [ -n "$o" ]; then BS="upgrade distro package $o"; BC=${PKGUP:+$PKGUP $o}
    else BS="upgrade pip/certifi that ship $1 (installed outside the package manager)"; BC=; fi
  }
  py_steps() {
    if [ "$prefix" = /usr ]; then
      ps=$CAFIX; pc=$CACMD
    else
      ps="upgrade pip and certifi in $prefix with the tool that manages it"
      pc=$(pyfix "$py" "$prefix" "$em" "$(kv inst_certifi "$out")" 0 pip certifi)
    fi
  }
  py_trust() { FS=$CAFIX; FC=$CACMD; }
  CURL_CANDS=(curl)
  GIT_CANDS=(git)
  OPENSSL_CANDS=(openssl)
  PY_PATHS=(/usr/bin/python3{,.[0-9]*} /usr/local/bin/python3{,.[0-9]*} /opt/python*/bin/python3
    ~/.pyenv/versions/*/bin/python3 ~/.local/share/uv/python/*/bin/python3 ~/.rye/py/*/bin/python3
    ~/.asdf/installs/python/*/bin/python3 ~/.local/share/mise/installs/python/*/bin/python3
    ~/miniconda3/bin/python ~/anaconda3/bin/python ~/miniforge3/bin/python ~/mambaforge/bin/python ~/micromamba/bin/python /opt/conda/bin/python
    ~/miniconda3/envs/*/bin/python ~/anaconda3/envs/*/bin/python ~/miniforge3/envs/*/bin/python ~/mambaforge/envs/*/bin/python
    ~/micromamba/envs/*/bin/python ~/.conda/envs/*/bin/python /opt/conda/envs/*/bin/python ~/.pixi/envs/*/bin/python
    ~/.local/share/pipx/venvs/*/bin/python ~/.local/pipx/venvs/*/bin/python ~/.local/share/uv/tools/*/bin/python
    ~/.virtualenvs/*/bin/python ~/.cache/pypoetry/virtualenvs/*/bin/python ~/.local/share/hatch/env/virtual/*/*/bin/python
    /home/linuxbrew/.linuxbrew/bin/python3{,.[0-9]*})
  NODE_CANDS=(node nodejs ~/.nvm/versions/node/*/bin/node ~/.volta/tools/image/node/*/bin/node
    ~/.local/share/fnm/node-versions/*/installation/bin/node /usr/local/n/versions/node/*/bin/node
    ~/.asdf/installs/nodejs/*/bin/node ~/.local/share/mise/installs/node/*/bin/node /home/linuxbrew/.linuxbrew/bin/node
    ~/.nodenv/versions/*/bin/node ~/.local/share/pnpm/nodejs/*/bin/node /snap/bin/node)
  JAVA_CANDS=(java ${JAVA_HOME:+"$JAVA_HOME/bin/java"} /usr/lib/jvm/*/bin/java /usr/java/*/bin/java /opt/java/*/bin/java
    ~/.sdkman/candidates/java/*/bin/java ~/.jdks/*/bin/java ~/.asdf/installs/java/*/bin/java ~/.local/share/mise/installs/java/*/bin/java)
  GO_CANDS=(go /usr/local/go/bin/go /usr/lib/go/bin/go ~/sdk/go*/bin/go ~/.local/share/mise/installs/go/*/bin/go
    ~/.asdf/installs/golang/*/go/bin/go /snap/bin/go)
else
  OSFIX="install latest macOS updates (System Settings > General > Software Update)"
  CERTPEM_FIX="back up /etc/ssl/cert.pem, remove 'AAA Certificate Services' and 'emSign ECC Root CA - G3' from it (see $REF)"
  BREWCA="brew update && brew upgrade ca-certificates"
  os_store() {
    hdr "macOS"
    info "macOS $(sw_vers -productVersion) build $(sw_vers -buildVersion) ($(uname -m))"
    [ $CLT = 1 ] && info "Xcode CLT: $(xcode-select -p)" || info "Xcode CLT not installed; /usr/bin python3/pip3/git skipped"
    res "macOS system trust (Safari, URLSession apps)" "$(nsurl_codes)" "$OSFIX"
  }
  os_bundles() {
    hdr "CA bundles"
    bundle "/etc/ssl/cert.pem (system curl/git/python3/perl/ruby/openssl)" /etc/ssl/cert.pem "$CERTPEM_FIX"
    if have brew; then
      BP=$(brew --prefix)
      for f in "$BP"/etc/ca-certificates/cert.pem "$BP"/etc/openssl@3/cert.pem "$BP"/etc/openssl@1.1/cert.pem "$BP"/etc/openssl/cert.pem; do
        bundle "Homebrew bundle" "$f" "" "$BREWCA"
      done
    fi
    for f in /opt/local/share/curl/curl-ca-bundle.crt /opt/local/etc/openssl/cert.pem; do
      bundle "MacPorts bundle" "$f" "" "sudo port selfupdate && sudo port upgrade curl-ca-bundle"
    done
    [ -d /nix ] && info "Nix present: nix-darwin users also follow the NixOS steps at $REF"
  }
  browsers() {
    for a in Safari "Google Chrome" Chromium "Microsoft Edge" "Brave Browser" Opera Vivaldi Arc Firefox; do
      [ -d "/Applications/$a.app" ] && info "$a $(defaults read "/Applications/$a.app/Contents/Info" CFBundleShortVersionString 2>/dev/null)"
    done
  }
  by() {
    local r b; r=$(rp "$1"); b=$(brewof "$r")
    case $r in
      */Cellar/*|/opt/homebrew/*) FS=; FC="$b update && $b upgrade ca-certificates" ;;
      /usr/*|/bin/*|/etc/*|/Library/Developer/*|/Applications/Xcode*) FS=$CERTPEM_FIX; FC= ;;
      /opt/local/*)            FS=; FC="sudo port selfupdate && sudo port upgrade curl-ca-bundle" ;;
      *)                       FS="update $1 or point it to a patched CA bundle"; FC= ;;
    esac
  }
  bfix() {
    BS=$ps; BC=$pc
    [ "$2" = pip ] && return
    case $1 in "$prefix"/*) ;; "$HOME"/*) BS="upgrade the user-site certifi ($1)"; BC=$([ "$em" = 1 ] || echo "$(q "$py") -m pip install --user -U certifi") ;; esac
  }
  py_steps() {
    case $prefix in
      /Library/Developer/*|/Applications/Xcode*|/System/*)
        ps="$CERTPEM_FIX; set PIP_CERT=/etc/ssl/cert.pem via sitecustomize.py (see $REF)"; pc= ;;
      *) ps="upgrade pip and certifi in $prefix"; pc=$(pyfix "$py" "$prefix" "$em" "$(kv inst_certifi "$out")" 0 pip certifi) ;;
    esac
  }
  py_trust() {
    case $prefix in
      /Library/Frameworks/*) FS=; FC=$(q "/Applications/Python ${v%.*}/Install Certificates.command") ;;
      *) by "$py" ;;
    esac
    [ -n "$ts" ] && { FS=$OSFIX; FC=; }
  }
  CURL_CANDS=(curl /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl /opt/local/bin/curl)
  GIT_CANDS=(git /opt/homebrew/bin/git /usr/local/bin/git)
  OPENSSL_CANDS=(openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl)
  PY_PATHS=(/usr/bin/python3 /opt/homebrew/bin/python3{,.[0-9]*} /usr/local/bin/python3{,.[0-9]*} /opt/homebrew/opt/python@*/bin/python3
    /Library/Frameworks/Python.framework/Versions/*/bin/python3 /opt/local/bin/python3{,.[0-9]*}
    ~/.pyenv/versions/*/bin/python3 ~/.local/share/uv/python/*/bin/python3 ~/.rye/py/*/bin/python3
    ~/.asdf/installs/python/*/bin/python3 ~/.local/share/mise/installs/python/*/bin/python3
    ~/miniconda3/bin/python ~/anaconda3/bin/python ~/miniforge3/bin/python ~/mambaforge/bin/python ~/micromamba/bin/python
    /opt/miniconda3/bin/python /opt/anaconda3/bin/python /opt/homebrew/Caskroom/miniforge/base/bin/python
    ~/miniconda3/envs/*/bin/python ~/anaconda3/envs/*/bin/python ~/miniforge3/envs/*/bin/python /opt/miniconda3/envs/*/bin/python
    ~/mambaforge/envs/*/bin/python ~/micromamba/envs/*/bin/python ~/.conda/envs/*/bin/python ~/.pixi/envs/*/bin/python
    ~/.local/share/pipx/venvs/*/bin/python ~/.local/pipx/venvs/*/bin/python ~/.local/share/uv/tools/*/bin/python
    ~/.virtualenvs/*/bin/python ~/Library/Caches/pypoetry/virtualenvs/*/bin/python
    "$HOME/Library/Application Support/hatch/env/virtual"/*/*/bin/python)
  NODE_CANDS=(node ~/.nvm/versions/node/*/bin/node ~/.volta/tools/image/node/*/bin/node
    ~/.local/share/fnm/node-versions/*/installation/bin/node "$HOME/Library/Application Support/fnm/node-versions"/*/installation/bin/node
    /usr/local/n/versions/node/*/bin/node ~/.asdf/installs/nodejs/*/bin/node ~/.local/share/mise/installs/node/*/bin/node
    /opt/homebrew/opt/node*/bin/node /usr/local/opt/node*/bin/node ~/.nodenv/versions/*/bin/node
    "$HOME/Library/pnpm/nodejs"/*/bin/node)
  JAVA_CANDS=(${JAVA_HOME:+"$JAVA_HOME/bin/java"} /Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java
    ~/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java /opt/homebrew/opt/openjdk*/bin/java /usr/local/opt/openjdk*/bin/java
    ~/.sdkman/candidates/java/*/bin/java ~/.jdks/*/bin/java ~/.local/share/mise/installs/java/*/bin/java)
  GO_CANDS=(go /usr/local/go/bin/go ~/sdk/go*/bin/go /opt/homebrew/opt/go*/bin/go ~/.local/share/mise/installs/go/*/bin/go)
fi

cat > "$T/probe.py" <<'EOF'
import sys, ssl
try:
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    print("ver=" + sys.version.split()[0]); sys.exit()
VerifyError = getattr(ssl, "SSLCertVerificationError", None)
REJECT = (2, 19, 20, 21, 23, 28, 0x80092010, 0x800B0109, 0x800B010A, 0x800B010C, 0x800B0111)  # OpenSSL: issuer unknown/untrusted, self-signed in chain, revoked, rejected; Windows (truststore): revoked, untrusted root, chaining, revoked, explicit distrust
TRUSTSTORE = ssl.SSLContext.__module__.startswith("truststore")
def rejected(r):
    return r.verify_code in REJECT or TRUSTSTORE and any(s in str(r.verify_message or r).lower() for s in ("revoked", "not trusted", "untrusted", "distrust"))
def plain():
    global TRUSTSTORE
    if TRUSTSTORE:
        import truststore; truststore.extract_from_ssl(); TRUSTSTORE = False
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
                out += "C" if rejected(r) else "N"
            else:
                out += "C" if "CERTIFICATE_VERIFY_FAILED" in str(r) else "N"
    return out
args = sys.argv[1:]
if args[:1] == ["--cafile"]:
    plain(); print(codes(args[2:], args[1])); sys.exit()
import os, site, sysconfig
venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
print("ver=" + sys.version.split()[0])
if TRUSTSTORE:
    print("ts=1")
print("sys=" + codes(args))
plain()
for key, mod in (("certifi", "certifi"), ("pipcertifi", "pip._vendor.certifi")):
    try:
        m = __import__(mod, fromlist=["where"])
        print("%s=%s|%s|%s" % (key, getattr(m, "__version__", "?"), m.where(), codes(args, m.where())))
    except Exception:
        pass
print("em=%d" % (not venv and os.path.exists(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))))
try:
    from importlib.metadata import distribution
except ImportError:
    sys.exit()
user = getattr(site, "getusersitepackages", lambda: "?")()
for n in ("certifi", "uv", "deno"):
    try:
        d = distribution(n)
        inst = (d.read_text("INSTALLER") or "pip").strip()
        print("inst_%s=%s" % (n, inst))
        loc = os.path.realpath(str(d.locate_file("")))
        usr = loc == os.path.realpath(user)
        if not (usr or loc.startswith(os.path.realpath(sys.prefix) + os.sep)):
            continue
        for f in d.files or []:
            if f.name in (n, n + ".exe"):
                print("tool=%s|%s|%d" % (os.path.realpath(str(d.locate_file(f))), inst, usr))
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
r(){ case $* in *'local issuer'*|*'issuer certificate'*|*'self-signed certificate in'*|*'self signed certificate in'*|*'locally verify'*|*'unable to verify the first'*|*revoked*|*REVOKED*|*UNTRUSTED*|*'not trusted'*|*'server certificate verification failed'*) printf C;; *) printf N;; esac; }; t(){ if command -v curl >/dev/null 2>&1; then T=curl; e=$(curl -sS -o /dev/null -m 15 $1 2>&1) && printf S || r $e; elif command -v wget >/dev/null 2>&1; then T=wget; e=$(wget -q -T 15 -O /dev/null $1 2>&1); c=$?; if [ $c = 0 ] || [ $c = 8 ]; then printf S; else r $e; fi; elif command -v python3 >/dev/null 2>&1; then T=python3; e=$(python3 -c 'import sys,urllib.request as u;u.urlopen(sys.argv[1],timeout=15)' $1 2>&1); c=$?; if [ $c = 0 ] || echo $e | grep -q HTTPError; then printf S; else r $e; fi; else T=none; printf X; fi; }; for u; do t $u; done; echo; echo $( (dpkg-query -W -f='${Version}' ca-certificates || apk info -v ca-certificates || rpm -q ca-certificates) 2>/dev/null | head -1); echo $T
EOF

echo "eMudhra CA exposure check ($OSNAME) - ref: $REF"
echo "Codes: $NT test hosts ($TEST_HOSTS) + control; S=TLS accepted, C=rejected untrusted/revoked, N=other error"

os_store

hdr "Tools for bundle tests"
for py in $(cands python3 python); do "$py" -c 'import ssl; ssl.create_default_context' 2>/dev/null </dev/null && { PYB=$py; break; }; done
CURL1=$(cands curl | head -1)
info "bundle tester: ${PYB:-${CURL1:-none}}"

os_bundles

hdr "curl"
while IFS= read -r c <&3; do
  info "$("$c" --version 2>/dev/null </dev/null | head -1) ($c)"
  by "$c"; res "curl ($c)" "$(curl_codes "$c")" "$FS" "$FC"
done 3< <(cands "${CURL_CANDS[@]}")

hdr "git"
while IFS= read -r g <&3; do
  info "$("$g" --version 2>/dev/null </dev/null) ($g)"
  by "$g"; res "git ls-remote ($g)" "$(git_codes "$g")" "$FS" "$FC"
done 3< <(cands "${GIT_CANDS[@]}")

hdr "openssl"
while IFS= read -r o <&3; do
  info "$("$o" version 2>/dev/null </dev/null) ($o)"
  by "$o"; res "openssl s_client ($o)" "$(openssl_codes "$o")" "$FS" "$FC"
done 3< <(cands "${OPENSSL_CANDS[@]}")

hdr "Python / pip / certifi"
CONDA=$(for m in conda mamba micromamba; do have $m && { echo $m; break; }; done)
PY_SEEN='|'
while IFS= read -r py <&3; do
  prefix=$(to 30 "$py" -c 'import os,sys;print(os.path.realpath(sys.prefix))' 2>/dev/null </dev/null)
  [ -z "$prefix" ] && { warn "python ($py): did not run"; continue; }
  case $PY_SEEN in *"|$prefix|"*) continue ;; esac
  PY_SEEN="$PY_SEEN$prefix|"
  out=$(to 600 "$py" "$T/probe.py" $URLS 2>/dev/null </dev/null)
  v=$(kv ver "$out"); em=$(kv em "$out"); ts=$(kv ts "$out")
  [ -z "$(kv sys "$out")" ] && { warn "python ${v:-?} ($py): too old to test or probe failed"; continue; }
  py_steps
  case $prefix in
    "$HOME"/.pixi/envs/*) ec="pixi global update $(basename "$prefix")" ;;
    *)                    ec=${CONDA:+$CONDA update -y -p $(q "$prefix") ca-certificates certifi openssl} ;;
  esac
  if [ -z "$ts" ] && [ -d "$prefix/conda-meta" ]; then
    res "python $v ($py) default trust${ts:+ (truststore)}" "$(kv sys "$out")" "update ca-certificates, certifi and openssl in $prefix" "$ec"
  else
    py_trust
    res "python $v ($py) default trust${ts:+ (truststore)}" "$(kv sys "$out")" "$FS" "$FC"
  fi
  c=$(kv certifi "$out")
  if [ -n "$c" ]; then
    rest=${c#*|}; cp=${rest%|*}
    bfix "$cp" certifi; res "certifi ${c%%|*} bundle ($cp)" "${rest##*|}" "$BS" "$BC"
    SEEN_BUNDLES="$SEEN_BUNDLES$(rp "$cp")|"
  fi
  c=$(kv pipcertifi "$out")
  [ -n "$c" ] && { rest=${c#*|}; bfix "${rest%|*}" pip; res "pip vendored certifi ${c%%|*} ($py)" "${rest##*|}" "$BS" "$BC"; }
  while IFS='|' read -r tp ti tu; do
    [ -n "$tp" ] && TOOLFIX+=("$tp|$(pyfix "$py" "$prefix" "$em" "$ti" "$tu" "$(basename "$tp")")")
  done < <(printf '%s\n' "$out" | sed -n 's/^tool=//p')
done 3< <(cands --keep-links "${PY_NAMES[@]}" "${PY_PATHS[@]}")

hdr "Node.js / npm"
while IFS= read -r n <&3; do
  v=$("$n" -v 2>/dev/null </dev/null) || continue
  res "node $v ($n)" "$(to 120 "$n" "$T/probe.js" $URLS 2>/dev/null </dev/null)" "upgrade Node.js to a patched release (>= 22.23.4 | 24.22.1 | 26.12.1)"
  [ -x "$(dirname "$n")/npm" ] && info "npm $("$(dirname "$n")/npm" -v 2>/dev/null </dev/null) ($(dirname "$n")/npm)"
done 3< <(cands "${NODE_CANDS[@]}")

hdr "Java"
while IFS= read -r j <&3; do
  jv=$(to 30 "$j" -version 2>&1 </dev/null | sed -nE 's/.*version "([^"]+)".*/\1/p' | head -1)
  case $jv in 1.*) jv=${jv#1.}; jv=${jv/_/.} ;; esac
  need "java ($j)" "$jv" 1 "upgrade JDK" 27.0.1.0.2 25.0.5.0.2 21.0.13.0.2 17.0.21.0.2 11.0.33.0.2 8.0.511
done 3< <(cands "${JAVA_CANDS[@]}")

hdr "Go"
while IFS= read -r g <&3; do
  need "go ($g)" "$("$g" version 2>/dev/null </dev/null | ver)" 2 "upgrade Go" 1.27.3 1.26.10
done 3< <(cands "${GO_CANDS[@]}")

hdr "Other tools (PATH and python envs)"
tool uv 0.13.4 "self update"
tool pixi 0.82.1 self-update
tool rustup 1.29.2 "self update"
tool deno 2.9.8 upgrade
tool mise 2026.10.17 self-update
tool claude 2.1.303 update
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
GIT1=$(cands "${GIT_CANDS[@]}" | head -1)
if [ -n "$GIT1" ]; then
  if [ "$("$GIT1" config --bool --get http.sslVerify)" = false ]; then
    case $("$GIT1" config --show-scope --get http.sslVerify 2>/dev/null) in
      global*) fail "git http.sslVerify=false (global)" "" "git config --global --unset-all http.sslVerify" ;;
      *)       fail "git http.sslVerify=false" "remove it where 'git config --show-origin --get http.sslVerify' points" ;;
    esac
  fi
  c=$("$GIT1" config --get http.sslCAInfo) && bundle "git http.sslCAInfo" "$c" "point http.sslCAInfo to a patched bundle"
fi
if have npm; then
  if [ "$(to 30 npm config get strict-ssl 2>/dev/null)" = false ]; then
    if grep -Eqs '^[[:space:]]*strict-ssl[[:space:]]*=[[:space:]]*false' "$(to 30 npm config get userconfig 2>/dev/null)"; then
      fail "npm strict-ssl=false (user config)" "" "npm config set strict-ssl true && [ \"\$(npm config get strict-ssl)\" = true ]"
    else
      fail "npm strict-ssl=false" "remove strict-ssl=false from the npmrc that sets it ('npm config ls -l' shows the source)"
    fi
  fi
  c=$(to 30 npm config get cafile 2>/dev/null); [ -n "$c" ] && [ "$c" != null ] && [ "$c" != undefined ] && bundle "npm cafile" "$c" "update npm cafile bundle"
fi
if [ -n "$PYB" ]; then
  pc=$(to 30 "$PYB" -m pip config list 2>/dev/null </dev/null)
  c=$(printf '%s\n' "$pc" | sed -n "s/^[a-z]*\.cert='\(.*\)'$/\1/p" | head -1); [ -n "$c" ] && bundle "pip config cert" "$c" "update pip cert bundle"
  printf '%s\n' "$pc" | grep -q trusted-host && warn "pip trusted-host set (TLS verify off for those hosts)" "remove trusted-host from pip config"
fi

hdr "Browsers (not tested; see SUMMARY)"
browsers

hdr "Containers (docker, podman)"
if [ $NO_DOCKER = 1 ]; then
  info "skipped (--no-docker)"
elif ! have docker && ! have podman; then
  info "docker/podman not installed"
fi
for eng in docker podman; do
  [ $NO_DOCKER = 1 ] && break
  have $eng || continue
  ev=$($eng --version 2>/dev/null </dev/null)
  case $eng:$ev in docker:*odman*) continue ;; esac
  if ! to 20 $eng info >/dev/null 2>&1 </dev/null; then
    warn "$eng: engine not reachable; images/containers not checked (start it, re-run)"; continue
  fi
  info "$ev"
  [ -z "$($eng images -q 2>/dev/null | head -1)" ] && info "$eng: no local images"
  [ -z "$($eng ps -q 2>/dev/null | head -1)" ] && info "$eng: no running containers"
  while IFS= read -r img <&3; do
    probe "$eng image $img" "$(to 300 $eng run --rm --pull=never --entrypoint sh "$img" -c "$IMG_SH" sh $URLS 2>/dev/null </dev/null)" \
      "rebuild/pull $img with updated ca-certificates"
  done 3< <($eng images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u)
  while IFS='|' read -r name img <&3; do
    probe "$eng container $name ($img)" "$(to 300 $eng exec "$name" sh -c "$IMG_SH" sh $URLS 2>/dev/null </dev/null)" \
      "rebuild $img with updated ca-certificates, then redeploy $name"
  done 3< <($eng ps --format '{{.Names}}|{{.Image}}' 2>/dev/null)
done

summary
[ $FIXFAIL = 1 ] && exit 3
[ ${#ISSUES[@]} -gt 0 ] && exit 1
[ ${#UNTESTED[@]} -gt 0 ] && exit 2
exit 0
