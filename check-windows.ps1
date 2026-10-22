<#
.SYNOPSIS
  eMudhra compromised-intermediate exposure check for Windows (plus WSL distros, Docker Desktop, images and running containers).
  Ref: https://emudhra.we-have-a-problem.com/

.DESCRIPTION
  Usage:   powershell -ExecutionPolicy Bypass -File .\check-windows.ps1 [-Fix]
  Method:  1) compare installed versions against the patched-version table
           2) live TLS test: each client connects to the 12 advisory test hosts
              (6 compromised TLS intermediates x 2 roots: emSign Root TLS G3 and the
              Sectigo "AAA Certificate Services" cross-sign) plus a control host.
              A patched client must REJECT all 12.
           Browsers are not driven; the SUMMARY gives a manual test.
  Codes:   13 letters per client = 12 test hosts (order of $TestHosts), then control (example.com)
           S = TLS accepted   C = rejected as untrusted/revoked   N = network/other error
           any S in the first 12 = FAIL;  CCCCCCCCCCCC + S = OK;  anything else = NOT VERIFIED
  WSL:     each distro is scanned with check-unix.sh if it sits next to this script,
           else with a short built-in probe (curl/wget/python3 + ca-certificates version).
  Output:  [OK] / [INFO] / [WARN] / [FAIL] lines, then a SUMMARY: issues, fix commands, manual steps.
  -Fix:    after the checks, run the fix commands (only package-manager / self-update
           commands that are known to be correct for how each item was installed).
  Exit:    0 = no issues, 1 = issues found, 2 = no issues but some checks not verified;
           with -Fix: 3 = a fix command failed; else the codes above, from the scan before the fixes (re-run to verify)
#>
param([switch]$Fix)

$ErrorActionPreference = 'SilentlyContinue'
$Ref = 'https://emudhra.we-have-a-problem.com/'
$TestHosts = 'dv-g3b', 'dv-g3b-aaa', 'dv-g3c', 'dv-g3c-aaa', 'ov-g3b', 'ov-g3b-aaa', 'ov-g3c', 'ov-g3c-aaa', 'ev-g3b', 'ev-g3b-aaa', 'ev-g3c', 'ev-g3c-aaa'
$Urls = @($TestHosts | ForEach-Object { "https://$_-emudhra.we-have-a-problem.com/" }) + 'https://example.com/'
$NT = $TestHosts.Count
$Issues = New-Object System.Collections.Generic.List[string]
$Untested = New-Object System.Collections.Generic.List[string]
$Cmds = New-Object System.Collections.Generic.List[string]
$Steps = New-Object System.Collections.Generic.List[string]
$ToolFix = @{}
$SeenBundles = @{}
$WinFix = "install Windows updates; else run Block-EmudhraCompromisedCA.ps1 elevated (see $Ref)"
$GitFix = 'update Git for Windows when a release with a patched ca-bundle.crt ships (git update-git-for-windows)'

# SHA-256 of the 16 compromised intermediates + Sectigo cross-signs (impacted-intermediates.json)
$Intermediates = @(
  '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493', '45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE',
  '98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B', '5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699',
  'E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838', '579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512',
  '0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19', '62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72',
  'CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F', '7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489',
  '432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3', 'FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F',
  '9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4', 'A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8',
  '4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1', '84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD'
)
# SHA-256 of the affected roots (roots.json)
$Roots = @{
  '7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D' = 'emSign Root TLS CA - G3'
  'F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5' = 'emSign Root CS CA - G3'
  'D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4' = 'AAA Certificate Services'
  '86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B' = 'emSign ECC Root CA - G3'
}

function Ok($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Info($m) { Write-Host "[INFO] $m" }
function Fail($m, $step, $cmd) { Write-Host "[FAIL] $m" -ForegroundColor Red; Note $m $step $cmd }
function Warn($m, $step, $cmd) { Write-Host "[WARN] $m" -ForegroundColor Yellow; if ($step -or $cmd) { Note $m $step $cmd } else { $Untested.Add($m) } }
function Q($p) { "'" + ("$p" -replace "'", "''") + "'" }

# Note: record an issue; $cmd = command safe to run with -Fix, else $step is a manual step
function Note($m, $step, $cmd) {
  if ($cmd) {
    if (-not $Cmds.Contains($cmd)) { $Cmds.Add($cmd) }
    $Issues.Add("$m  -> cmd $($Cmds.IndexOf($cmd) + 1)")
  } else {
    if (-not $Steps.Contains("$step")) { $Steps.Add("$step") }
    $Issues.Add("$m  -> step $($Steps.IndexOf("$step") + 1)")
  }
}
function Hdr($m) { Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Ver($text) { [regex]::Match("$text", '\d+(\.\d+)+').Value }
function Kv($lines, $key) { (@($lines) | Where-Object { "$_" -like "$key=*" } | Select-Object -First 1) -replace "^$key=", '' }
function Lines($result) { @("$($result.Out)" -split "`r?`n") }
function Redact($s) { "$s" -replace '//[^/@]*@', '//***@' }

# Rejected: true only for untrusted-issuer / revoked errors (not generic TLS or network errors)
function Rejected($msg) { "$msg" -match 'local issuer|issuer certificate|self.signed certificate in|locally verify|unable to verify the first|revoked|untrusted|not trusted|server certificate verification failed' }

# Run: start a native exe with a hard deadline; returns .Out, .Err, .Code (-1 = timed out, -2 = could not start)
function Run($exe, [string[]]$arguments, [int]$sec = 60) {
  $psi = New-Object Diagnostics.ProcessStartInfo $exe
  $psi.Arguments = (@($arguments) | ForEach-Object {
    if ($_ -eq '' -or $_ -match '[\s"]') { '"' + (($_ -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' } else { $_ }
  }) -join ' '
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  try { $p = [Diagnostics.Process]::Start($psi) } catch { return [pscustomobject]@{ Out = ''; Err = "$_"; Code = -2 } }
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($sec * 1000)) {
    try { $p.Kill($true) } catch { & taskkill.exe /T /F /PID $p.Id 2>&1 | Out-Null }
    return [pscustomobject]@{ Out = ''; Err = 'timeout'; Code = -1 }
  }
  [pscustomobject]@{ Out = $out.Result; Err = $err.Result; Code = $p.ExitCode }
}

# VGe A B: true if version A >= version B (numeric fields, any separators)
function VGe($a, $b) {
  $x = @([regex]::Matches("$a", '\d+') | ForEach-Object { [long]$_.Value })
  $y = @([regex]::Matches("$b", '\d+') | ForEach-Object { [long]$_.Value })
  for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) {
    $p = 0; $q = 0
    if ($i -lt $x.Count) { $p = $x[$i] }
    if ($i -lt $y.Count) { $q = $y[$i] }
    if ($p -ne $q) { return $p -gt $q }
  }
  $true
}

# Branch V N: first N numeric fields of V (e.g. Branch 22.1.0 1 -> 22)
function Branch($v, $n) { (@([regex]::Matches("$v", '\d+') | ForEach-Object Value) | Select-Object -First $n) -join '.' }

# Need: OK if version >= patch of its branch, or >= all patches; pre-release builds fail
function Need($label, $v, $depth, $fx, [string[]]$patched) {
  if (-not $v) { Warn "${label}: version unknown"; return }
  $want = $patched -join ' | '
  if ("$v" -match '-(rc|beta|alpha|pre|ea|nightly|canary)') { Fail "$label $v (pre-release)" "$fx to a stable release (>= $want)"; return }
  $all = $true
  foreach ($p in $patched) {
    if (-not (VGe $v $p)) { $all = $false; continue }
    if ((Branch $v $depth) -eq (Branch $p $depth)) { Ok "$label $v"; return }
  }
  if ($all) { Ok "$label $v" } else { Fail "$label $v" "$fx (>= $want)" }
}

# UpCmd: upgrade command for the copy of a tool at $path, by how it was installed (empty = unsure)
function UpCmd($path, $self) {
  $name = [IO.Path]::GetFileNameWithoutExtension($path)
  $key = (Get-Item -LiteralPath $path).FullName.ToLower()
  if ($ToolFix.ContainsKey($key)) { return $ToolFix[$key] }
  switch -Regex ($path) {
    '\\scoop\\' {
      $m = [regex]::Match("$path`n$(Get-Content -Raw -LiteralPath ([IO.Path]::ChangeExtension($path, 'shim')))", '\\scoop\\apps\\([^\\]+)\\')
      return $(if ($m.Success) { "scoop update $($m.Groups[1].Value)" } else { '' })
    }
    '\\chocolatey\\' { return '' }
    '\\WinGet\\|\\WindowsApps\\' { return '' }
    '\\mise\\installs\\([^\\]+)\\' { return "mise upgrade $($Matches[1])" }
    '\\\.pixi\\bin\\' { if ($name -ne 'pixi') { return "pixi global update $name" } }
    '\\\.cargo\\bin\\' { if ($name -ne 'rustup') { return '' } }
  }
  if ($path -match '\.(cmd|ps1)$') {
    $m = [regex]::Match((Get-Content -Raw -LiteralPath $path), 'node_modules\\((@[^\\]+\\)?[^\\"]+)')
    if (-not $m.Success) { return '' }
    $pkg = $m.Groups[1].Value -replace '\\', '/'
    $dir = Split-Path $path
    if ($path -match '\\pnpm\\') { return "pnpm add -g $pkg" }
    if ($path -match '\\\.bun\\') { return "bun add -g $pkg" }
    if ($path -match '\\Yarn\\') { return "yarn global add $pkg" }
    if ((Test-Path "$dir\node.exe") -and (Test-Path "$dir\node_modules\npm\bin\npm-cli.js")) { return "& $(Q "$dir\node.exe") $(Q "$dir\node_modules\npm\bin\npm-cli.js") install -g --prefix $(Q $dir) $pkg" }
    return "npm install -g --prefix $(Q $dir) $pkg"
  }
  if ($path -like "$env:USERPROFILE\*" -and $path -match '\\\.(local|deno|pixi|cargo)\\bin\\[^\\]+$') { "& $(Q $path) $self" } else { '' }
}

# Tool: version-check every copy of a tool (PATH and python envs); fix by install method
function Tool($name, $min, $self) {
  $extra = @($ToolFix.Keys | Where-Object { [IO.Path]::GetFileNameWithoutExtension($_) -eq $name })
  foreach ($p in (Cands @("$name.exe", "$name.cmd") $extra)) {
    $v = Ver (Run $p @('--version') 30).Out
    if (-not $v -and $p -match '\.cmd$') { $v = Ver (& $p --version 2>$null) }
    if (-not $v) { Warn "$name ($p): version unknown"; continue }
    if (VGe $v $min) { Ok "$name $v ($p)" } else { Fail "$name $v ($p) (need >= $min)" "upgrade $p with the tool that installed it" (UpCmd $p $self) }
  }
}

# PyFix: command that upgrades $pkgs in the env of $py (pipx / uv tool / conda / uv / pip, user or env install)
function PyFix($py, $prefix, $em, $inst, $user, [string[]]$pkgs) {
  $p = $pkgs -join ' '
  if ($prefix -match '\\pipx\\(pipx\\)?venvs\\([^\\]+)') { return "`$h = `$env:PIPX_HOME; `$env:PIPX_HOME = $(Q ($prefix -replace '\\venvs\\[^\\]+$')); pipx runpip $($Matches[2]) install -U $p; `$env:PIPX_HOME = `$h" }
  if ($prefix -match '\\uv\\tools\\([^\\]+)') { return "uv tool upgrade $($Matches[1])" }
  if ($prefix -like "$env:USERPROFILE\.pixi\envs\*") { return "pixi global update $(Split-Path $prefix -Leaf)" }
  if ($em -eq '1') { return '' }
  if ($user -eq '1') { return "& $(Q $py) -m pip install --user -U $p" }
  switch ($inst) {
    'conda' { if ($Conda) { "$Conda update -y -p $(Q $prefix) $p" } }
    'uv' { "uv pip install -p $(Q $py) -U $p" }
    default { "& $(Q $py) -m pip install -U $p" }
  }
}

# Res: CODES = one letter per test host, then the control host
function Res($label, $codes, $step, $cmd) {
  $c = "$codes".Trim()
  $tests = if ($c.Length -gt 1) { $c.Substring(0, $c.Length - 1) } else { '' }
  $n = @($tests.ToCharArray() | Where-Object { $_ -eq 'S' }).Count
  if ($n -gt 0) { Fail "${label}: TRUSTS $n/$NT compromised chains [$c]" $step $cmd }
  elseif ($c -ceq ('C' * $NT + 'S')) { Ok "${label}: rejects all $NT compromised chains" }
  else { Warn "${label}: not verified [$(if ($c) { $c } else { 'no output' })]" }
}

# Cands: unique executables from PATH names and explicit paths/globs
function Cands([string[]]$names, [string[]]$globs) {
  $seen = @{}
  $list = @(foreach ($n in $names) { Get-Command $n -All -CommandType Application | ForEach-Object Source }) +
          @(foreach ($g in $globs) { if ($g) { Resolve-Path $g | ForEach-Object Path } })
  foreach ($p in $list) {
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
    $key = (Get-Item -LiteralPath $p).FullName.ToLower()
    if ($seen[$key]) { continue }
    $seen[$key] = 1
    $p
  }
}

function CurlCodes($exe, [string[]]$extra) {
  -join ($Urls | ForEach-Object {
    $r = Run $exe (@($extra) + @('-sS', '-o', 'NUL', '-m', '15', $_)) 30
    if ($r.Code -eq 0) { 'S' } elseif (Rejected $r.Err) { 'C' } else { 'N' }
  })
}

function GitCodes($exe) {
  $env:GIT_TERMINAL_PROMPT = '0'
  -join ($Urls | ForEach-Object {
    $r = Run $exe @('-c', 'credential.helper=', 'ls-remote', $_) 45
    if ($r.Code -eq 0) { 'S' }
    elseif (Rejected $r.Err) { 'C' }
    elseif ($r.Err -match 'not found|not valid|returned error|Authentication|Username|repository') { 'S' }
    else { 'N' }
  })
}

# openssl verify codes 2/19/20/21/23/28 = issuer unknown/untrusted, self-signed in chain, revoked, rejected
function OpensslCodes($exe) {
  -join ($Urls | ForEach-Object {
    $h = ([uri]$_).Host
    $r = Run $exe @('s_client', '-connect', "${h}:443", '-servername', $h) 30
    $v = [regex]::Match("$($r.Out)", 'Verify return code: (\d+)').Groups[1].Value
    if ($v -eq '0') { 'S' } elseif (@('2', '19', '20', '21', '23', '28') -contains $v) { 'C' } else { 'N' }
  })
}

# Windows trust (CryptoAPI chain engine + Disallowed store), as used by .NET / PowerShell / Schannel apps.
# The TLS callback records the policy errors and chain status Windows computed, then lets the handshake finish.
function NetCodes {
  -join ($Urls | ForEach-Object {
    $h = ([uri]$_).Host; $script:chainResult = ''; $tcp = $null
    try {
      $tcp = New-Object Net.Sockets.TcpClient
      if ($tcp.ConnectAsync($h, 443).Wait(15000)) {
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, [Net.Security.RemoteCertificateValidationCallback] {
          param($sender, $cert, $chain, $errors)
          $script:chainResult = "$errors " + (@($chain.ChainStatus | ForEach-Object Status) -join ' ')
          $true
        })
        $ssl.ReadTimeout = 15000
        $ssl.AuthenticateAsClient($h)
        $ssl.Dispose()
      }
    } catch {} finally { if ($tcp) { $tcp.Dispose() } }
    if ($script:chainResult -match '^None\s*$') { 'S' }
    elseif ($script:chainResult -match 'UntrustedRoot|Revoked|PartialChain|NotTrusted|ExplicitDistrust') { 'C' }
    else { 'N' }
  })
}

# Probe: report an in-container test (lines: codes, ca-certificates version, client used)
function Probe($label, $lines, $fx) {
  $codes = "$(@($lines)[0])".Trim(); $pkg = "$(@($lines)[1])".Trim(); $via = "$(@($lines)[2])".Trim()
  if (-not $codes) { Warn "${label}: cannot run sh (distroless/other arch/timeout)" }
  elseif ($codes -match 'X') { Warn "${label}: no curl/wget/python3 inside; ca-certificates $pkg" }
  else { Res "$label via $via [ca-certificates $pkg]" $codes $fx }
}

# Bundle: live-test one PEM CA bundle file (once per path)
function Bundle($label, $file, $step, $cmd) {
  if (-not $file -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
  $key = (Get-Item -LiteralPath $file).FullName.ToLower()
  if ($SeenBundles[$key]) { return }
  $SeenBundles[$key] = 1
  if ($script:PyB) { Res "$label ($file)" (Run $script:PyB (@("$T\probe.py", '--cafile', $file) + $Urls) 300).Out $step $cmd }
  elseif ($script:GitCurl) { Res "$label ($file)" (CurlCodes $script:GitCurl @('--cacert', $file)) $step $cmd }
  else { Warn "$label ($file): no python/OpenSSL curl to test bundle" }
}

$T = Join-Path $env:TEMP ('emudhra-check-' + [guid]::NewGuid())
New-Item -ItemType Directory $T | Out-Null

Set-Content -Encoding ASCII "$T\probe.py" @'
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
'@

Set-Content -Encoding ASCII "$T\probe.js" @'
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
'@

# Runs inside each docker image/container or WSL distro with: sh -c $ImgSh sh URL...
# Prints 3 lines: codes, ca-certificates version, client used (first of curl, wget, python3)
# (no double quotes inside: Windows argument quoting would mangle them)
$ImgSh = @'
r(){ case $* in *'local issuer'*|*'issuer certificate'*|*'self-signed certificate in'*|*'self signed certificate in'*|*'locally verify'*|*'unable to verify the first'*|*revoked*|*REVOKED*|*UNTRUSTED*|*'not trusted'*|*'server certificate verification failed'*) printf C;; *) printf N;; esac; }; t(){ if command -v curl >/dev/null 2>&1; then T=curl; e=$(curl -sS -o /dev/null -m 15 $1 2>&1) && printf S || r $e; elif command -v wget >/dev/null 2>&1; then T=wget; e=$(wget -q -T 15 -O /dev/null $1 2>&1); c=$?; if [ $c = 0 ] || [ $c = 8 ]; then printf S; else r $e; fi; elif command -v python3 >/dev/null 2>&1; then T=python3; e=$(python3 -c 'import sys,urllib.request as u;u.urlopen(sys.argv[1],timeout=15)' $1 2>&1); c=$?; if [ $c = 0 ] || echo $e | grep -q HTTPError; then printf S; else r $e; fi; else T=none; printf X; fi; }; for u; do t $u; done; echo; echo $( (dpkg-query -W -f='${Version}' ca-certificates || apk info -v ca-certificates || rpm -q ca-certificates) 2>/dev/null | head -1); echo $T
'@

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

Write-Host "eMudhra CA exposure check (Windows) - ref: $Ref"
Write-Host "Codes: $NT test hosts ($($TestHosts -join ' ')) + control; S=TLS accepted, C=rejected untrusted/revoked, N=other error"

Hdr 'Windows trust'
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
Info "$($os.Caption) $($os.Version).$ubr; PowerShell $($PSVersionTable.PSVersion)"
$hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { Info "latest hotfix $($hf.HotFixID) installed $($hf.InstalledOn)" }

$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
if ($pol.DisableRootAutoUpdate -eq 1) { Fail 'policy DisableRootAutoUpdate=1 (no automatic CTL updates)' "ask IT; or run Block-EmudhraCompromisedCA.ps1 (see $Ref)" }
if ($pol.EnableDisallowedCertAutoUpdate -eq 0) { Fail 'policy EnableDisallowedCertAutoUpdate=0 (no Disallowed CTL updates)' "ask IT; or run Block-EmudhraCompromisedCA.ps1 (see $Ref)" }
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate'
if ($au.DisallowedCertLastSyncTime) {
  $sync = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($au.DisallowedCertLastSyncTime, 0))
  if ($sync -lt [datetime]'2026-10-20') { Warn "Disallowed CTL last sync $sync UTC (before Microsoft block on 2026-10-20)" 'check access to ctldl.windowsupdate.com; run Windows Update' }
  else { Ok "Disallowed CTL last sync $sync UTC" }
}

$sha = [Security.Cryptography.SHA256]::Create()
function StoreHashes($store) {
  @('LocalMachine', 'CurrentUser' | ForEach-Object { Get-ChildItem "Cert:\$_\$store" } |
    ForEach-Object { [BitConverter]::ToString($sha.ComputeHash($_.RawData)) -replace '-' })
}
$disallowed = StoreHashes 'Disallowed'
$blocked = @($Intermediates | Where-Object { $disallowed -contains $_ }).Count
Info "Disallowed store holds $blocked/16 compromised intermediates (CTL entries may not show here)"
$rootHashes = StoreHashes 'Root'
foreach ($h in $Roots.Keys) { if ($rootHashes -contains $h) { Info "root present in Root store: $($Roots[$h])" } }
Res '.NET/Schannel (Windows trust)' (NetCodes) $WinFix

$GitCurl = Cands @() @("$env:ProgramFiles\Git\ucrt64\bin\curl.exe", "$env:ProgramFiles\Git\mingw64\bin\curl.exe") | Select-Object -First 1
$PyB = Cands @('python.exe', 'python3.exe') @() | Where-Object { (Run $_ @('-c', 'import ssl; ssl.create_default_context') 30).Code -eq 0 } | Select-Object -First 1

Hdr 'curl'
foreach ($c in (Cands @('curl.exe') @("$env:SystemRoot\System32\curl.exe", "$env:ProgramFiles\Git\ucrt64\bin\curl.exe", "$env:ProgramFiles\Git\mingw64\bin\curl.exe"))) {
  Info "$((Lines (Run $c @('--version') 15))[0]) ($c)"
  $fx = if ($c -like "$env:SystemRoot\*") { $WinFix } elseif ($c -like '*\Git\*') { $GitFix } else { "update $c or its CA bundle" }
  Res "curl ($c)" (CurlCodes $c @()) $fx
  Bundle 'curl bundle' (Join-Path (Split-Path $c) 'curl-ca-bundle.crt') 'replace curl-ca-bundle.crt with a patched bundle'
}

Hdr 'git'
foreach ($g in (Cands @('git.exe') @("$env:ProgramFiles\Git\cmd\git.exe"))) {
  $backend = (Run $g @('config', '--get', 'http.sslBackend') 15).Out.Trim()
  Info "$((Run $g @('--version') 15).Out.Trim()) ($g) sslBackend=$(if ($backend) { $backend } else { 'default' })"
  $scope = (Run $g @('config', '--show-scope', '--get', 'http.sslBackend') 15).Out
  $fx = if ($backend -eq 'schannel') { $WinFix } elseif ($scope -match '^(local|worktree|command)') { "$GitFix; or set http.sslBackend=schannel where 'git config --show-origin --get http.sslBackend' points" } else { $GitFix }
  $cmd = if ($backend -ne 'schannel' -and $scope -notmatch '^(local|worktree|command)') { "& $(Q $g) config --global http.sslBackend schannel" }
  Res "git ls-remote ($g)" (GitCodes $g) $fx $cmd
}

Hdr 'openssl'
foreach ($o in (Cands @('openssl.exe') @("$env:ProgramFiles\Git\ucrt64\bin\openssl.exe", "$env:ProgramFiles\Git\usr\bin\openssl.exe", "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe"))) {
  Info "$((Run $o @('version') 15).Out.Trim()) ($o)"
  $fx = if ($o -like '*\Git\*') { $GitFix } else { "update the CA bundle $o uses" }
  Res "openssl s_client ($o)" (OpensslCodes $o) $fx
}

Hdr 'Python / pip / certifi'
$Conda = @('conda', 'mamba', 'micromamba') | Where-Object { Get-Command $_ } | Select-Object -First 1
$pyLauncher = @(& py -0p 2>$null | ForEach-Object { [regex]::Match("$_", '[A-Za-z]:\\.+?\.exe').Value } | Where-Object { $_ })
$pyGlobs = @(
  "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe", "$env:ProgramFiles\Python*\python.exe", 'C:\Python*\python.exe',
  "$env:APPDATA\uv\python\*\python.exe", "$env:USERPROFILE\.pyenv\pyenv-win\versions\*\python.exe",
  "$env:LOCALAPPDATA\mise\installs\python\*\python.exe", "$env:USERPROFILE\scoop\apps\python*\current\python.exe",
  "$env:USERPROFILE\pipx\venvs\*\Scripts\python.exe", "$env:LOCALAPPDATA\pipx\pipx\venvs\*\Scripts\python.exe",
  "$env:APPDATA\uv\tools\*\Scripts\python.exe", "$env:USERPROFILE\.virtualenvs\*\Scripts\python.exe",
  "$env:LOCALAPPDATA\pypoetry\Cache\virtualenvs\*\Scripts\python.exe", "$env:USERPROFILE\.conda\envs\*\python.exe",
  "$env:USERPROFILE\.pixi\envs\*\python.exe", "$env:USERPROFILE\.rye\py\*\python.exe"
) + @(foreach ($base in "$env:USERPROFILE\miniconda3", "$env:USERPROFILE\anaconda3", "$env:USERPROFILE\miniforge3", "$env:USERPROFILE\mambaforge",
    "$env:USERPROFILE\micromamba", "$env:ProgramData\miniconda3", "$env:ProgramData\anaconda3") {
  "$base\python.exe"; "$base\envs\*\python.exe"
}) + $pyLauncher
$pySeen = @{}
foreach ($py in (Cands @('python.exe', 'python3.exe') $pyGlobs)) {
  $prefix = (Run $py @('-c', 'import os,sys;print(os.path.realpath(sys.prefix))') 30).Out.Trim()
  if (-not $prefix) { if ($py -notlike '*\WindowsApps\*') { Warn "python ($py): did not run" }; continue }
  if ($pySeen[$prefix.ToLower()]) { continue }
  $pySeen[$prefix.ToLower()] = 1
  $out = Lines (Run $py (@("$T\probe.py") + $Urls) 600)
  $v = Kv $out 'ver'
  if (-not (Kv $out 'sys')) { Warn "python $v ($py): too old to test or probe failed"; continue }
  if (-not $script:PyB -and $py -notlike '*\Scripts\*') { $script:PyB = $py }
  $ps = "upgrade pip and certifi in $prefix"
  $em = Kv $out 'em'
  $pc = PyFix $py $prefix $em (Kv $out 'inst_certifi') 0 @('pip', 'certifi')
  if (-not (Kv $out 'ts') -and (Test-Path "$prefix\conda-meta")) {
    $ec = if ($prefix -like "$env:USERPROFILE\.pixi\envs\*") { "pixi global update $(Split-Path $prefix -Leaf)" } else { if ($Conda) { "$Conda update -y -p $(Q $prefix) ca-certificates certifi openssl" } }
    Res "python $v ($py) default trust" (Kv $out 'sys') "update ca-certificates, certifi and openssl in $prefix" $ec
  } else {
    if (Kv $out 'ts') { Res "python $v ($py) default trust (truststore: Windows trust)" (Kv $out 'sys') $WinFix }
    else { Res "python $v ($py) default trust (Windows Root store, ignores Disallowed)" (Kv $out 'sys') 'pip install -U certifi truststore and use truststore (honors Disallowed); or set SSL_CERT_FILE to a patched certifi bundle' }
  }
  $c = Kv $out 'certifi'
  if ($c) {
    $cv, $cp, $cc = $c -split '\|'
    $us, $uc = $ps, $pc
    if ($cp -notlike "$prefix\*" -and $cp -like "$env:APPDATA\*") { $us = "upgrade the user-site certifi ($cp)"; $uc = $(if ($em -ne '1') { "& $(Q $py) -m pip install --user -U certifi" }) }
    Res "certifi $cv bundle ($cp)" $cc $us $uc
    $SeenBundles[$cp.ToLower()] = 1
  }
  $c = Kv $out 'pipcertifi'
  if ($c) { $cv, $cp, $cc = $c -split '\|'; Res "pip vendored certifi $cv ($py)" $cc $ps $pc }
  foreach ($tl in @($out | Where-Object { $_ -like 'tool=*' })) {
    $tp, $ti, $tu = ($tl -replace '^tool=', '') -split '\|'
    if (-not $ToolFix.ContainsKey($tp.ToLower())) { $ToolFix[$tp.ToLower()] = PyFix $py $prefix $em $ti $tu @([IO.Path]::GetFileNameWithoutExtension($tp)) }
  }
}

Hdr 'Bundles shipped with Git for Windows'
foreach ($f in "$env:ProgramFiles\Git\ucrt64\etc\ssl\certs\ca-bundle.crt", "$env:ProgramFiles\Git\mingw64\etc\ssl\certs\ca-bundle.crt", "$env:ProgramFiles\Git\mingw64\ssl\certs\ca-bundle.crt", "$env:ProgramFiles\Git\usr\ssl\certs\ca-bundle.crt") {
  Bundle 'Git bundle (used when sslBackend=openssl)' $f $GitFix
}

Hdr 'Node.js / npm'
$nodeGlobs = "$env:ProgramFiles\nodejs\node.exe", "$env:NVM_HOME\v*\node.exe", "$env:APPDATA\nvm\v*\node.exe",
  "$env:LOCALAPPDATA\Volta\tools\image\node\*\node.exe", "$env:APPDATA\fnm\node-versions\*\installation\node.exe",
  "$env:LOCALAPPDATA\mise\installs\node\*\node.exe"
foreach ($n in (Cands @('node.exe') $nodeGlobs)) {
  $v = (Run $n @('-v') 15).Out.Trim()
  if (-not $v) { continue }
  Res "node $v ($n)" (Run $n (@("$T\probe.js") + $Urls) 120).Out 'upgrade Node.js to a patched release (>= 22.23.4 | 24.22.1 | 26.12.1)'
  $npm = Join-Path (Split-Path $n) 'npm.cmd'
  if (Test-Path $npm) { Info "npm $(& $npm -v 2>$null) ($npm)" }
}

Hdr 'Java'
$javaGlobs = "$env:JAVA_HOME\bin\java.exe", "$env:ProgramFiles\Java\*\bin\java.exe", "${env:ProgramFiles(x86)}\Java\*\bin\java.exe",
  "$env:ProgramFiles\Eclipse Adoptium\*\bin\java.exe", "$env:ProgramFiles\Microsoft\jdk-*\bin\java.exe", "$env:ProgramFiles\Zulu\*\bin\java.exe",
  "$env:ProgramFiles\Amazon Corretto\*\bin\java.exe", "$env:ProgramFiles\BellSoft\*\bin\java.exe", "$env:USERPROFILE\.jdks\*\bin\java.exe"
foreach ($j in (Cands @('java.exe') $javaGlobs)) {
  $jv = [regex]::Match((Run $j @('-version') 30).Err, 'version "([^"]+)"').Groups[1].Value
  if ($jv -like '1.*') { $jv = $jv.Substring(2) -replace '_', '.' }
  if ($jv) { Need "java ($j)" $jv 1 'upgrade JDK' @('27.0.1.0.2', '25.0.5.0.2', '21.0.13.0.2', '17.0.21.0.2', '11.0.33.0.2', '8.0.511') }
}

Hdr 'Go'
foreach ($g in (Cands @('go.exe') @("$env:ProgramFiles\Go\bin\go.exe", "$env:USERPROFILE\sdk\go*\bin\go.exe", "$env:LOCALAPPDATA\mise\installs\go\*\bin\go.exe"))) {
  Need "go ($g)" (Ver (Run $g @('version') 30).Out) 2 'upgrade Go' @('1.27.3', '1.26.10')
}

Hdr 'Other tools (PATH and python envs)'
Tool 'uv' '0.13.4' 'self update'
Tool 'pixi' '0.82.1' 'self-update'
Tool 'rustup' '1.29.2' 'self update'
Tool 'deno' '2.9.8' 'upgrade'
Tool 'mise' '2026.10.17' 'self-update'
Tool 'claude' '2.1.303' 'update'
if (Get-Command electron) { Need 'electron' ("$(& electron --version 2>$null)".Trim()) 1 'upgrade Electron' @('44.9.1', '43.8.1', '42.11.16') }
if (Get-Command bun) { Warn "bun $(& bun --version): vendor fix pending" "watch $Ref; avoid bun for TLS to untrusted hosts" }
if (Get-Command perl) {
  $pv = & perl -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>$null
  if ($pv) { if (VGe $pv '20261020') { Ok "perl Mozilla::CA $pv" } else { Fail "perl Mozilla::CA $pv" 'cpan Mozilla::CA (>= 20261020)' } }
}

Hdr 'Env / config'
foreach ($e in 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'PIP_CERT', 'NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO', 'HTTPS_PROXY') {
  $v = [Environment]::GetEnvironmentVariable($e)
  if ($v) {
    Info "$e=$(Redact $v)"
    if ($e -notmatch 'DIR|PROXY') { Bundle "`$env:$e" $v "replace $e file with a patched bundle" }
  }
}
if ($env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0') { Fail 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verify' 'remove NODE_TLS_REJECT_UNAUTHORIZED' }
if ($env:PYTHONHTTPSVERIFY -eq '0') { Fail 'PYTHONHTTPSVERIFY=0 disables TLS verify' 'remove PYTHONHTTPSVERIFY' }
if ($env:GIT_SSL_NO_VERIFY) { Fail 'GIT_SSL_NO_VERIFY set' 'remove GIT_SSL_NO_VERIFY' }
foreach ($rc in "$env:USERPROFILE\.curlrc", "$env:APPDATA\_curlrc") {
  if (Select-String -Path $rc -Pattern '^\s*(-k|--insecure|insecure)' -Quiet) { Fail "$rc disables TLS verify" "remove insecure/-k from $rc" }
}
if (Get-Command git) {
  if ((& git config --bool --get http.sslVerify) -eq 'false') {
    if ("$(& git config --show-scope --get http.sslVerify)" -like 'global*') { Fail 'git http.sslVerify=false (global)' '' 'git config --global --unset-all http.sslVerify' }
    else { Fail 'git http.sslVerify=false' "remove it where 'git config --show-origin --get http.sslVerify' points" }
  }
  $c = & git config --get http.sslCAInfo
  if ($c) { Bundle 'git http.sslCAInfo' $c 'point http.sslCAInfo to a patched bundle' }
}
if (Get-Command npm) {
  if ((& npm config get strict-ssl 2>$null) -eq 'false') {
    if (Select-String -Path "$(& npm config get userconfig 2>$null)" -Pattern '^\s*strict-ssl\s*=\s*false' -Quiet) { Fail 'npm strict-ssl=false (user config)' '' 'npm config set strict-ssl true; if ((npm config get strict-ssl) -ne ''true'') { throw ''strict-ssl is still false: another npmrc sets it (npm config ls -l)'' }' }
    else { Fail 'npm strict-ssl=false' "remove strict-ssl=false from the npmrc that sets it ('npm config ls -l' shows the source)" }
  }
  $c = & npm config get cafile 2>$null
  if ($c -and $c -notin 'null', 'undefined') { Bundle 'npm cafile' $c 'update npm cafile bundle' }
}
if ($PyB) {
  $pc = (Run $PyB @('-m', 'pip', 'config', 'list') 30).Out
  $c = [regex]::Match("$pc", "\.cert='([^']+)'").Groups[1].Value
  if ($c) { Bundle 'pip config cert' $c 'update pip cert bundle' }
  if ($pc -match 'trusted-host') { Warn 'pip trusted-host set (TLS verify off for those hosts)' 'remove trusted-host from pip config' }
}

Hdr 'Browsers (not tested; see SUMMARY)'
$pf86 = ${env:ProgramFiles(x86)}
foreach ($b in (Cands @() @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$pf86\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
    "$pf86\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe",
    "$env:LOCALAPPDATA\Programs\Opera\opera.exe", "$env:LOCALAPPDATA\Programs\Opera GX\opera.exe",
    "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe", "$env:ProgramFiles\Vivaldi\Application\vivaldi.exe", "$env:LOCALAPPDATA\Chromium\Application\chrome.exe",
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$pf86\Mozilla Firefox\firefox.exe"))) {
  $vi = (Get-Item -LiteralPath $b).VersionInfo
  Info "$($vi.ProductName) $($vi.ProductVersion) ($b)"
}

Hdr 'Containers (docker, podman)'
$dockerOk = $false
$engines = @('docker.exe', 'podman.exe' | ForEach-Object { Get-Command $_ | Select-Object -First 1 -ExpandProperty Source })
if (-not $engines) { Info 'docker/podman not installed' }
foreach ($eng in $engines) {
  $en = [IO.Path]::GetFileNameWithoutExtension($eng)
  $ev = (Run $eng @('--version') 20).Out.Trim()
  if ($en -eq 'docker' -and $ev -match 'podman') { continue }
  $ostype = (Run $eng @('info', '--format', $(if ($en -eq 'docker') { '{{.OSType}}' } else { '{{.Host.OS}}' })) 30).Out.Trim()
  if (-not $ostype) { Warn "${en}: engine not reachable; images/containers not checked (start it, re-run)"; continue }
  if ($ostype -ne 'linux') { Warn "${en}: $ostype-container mode; image test needs Linux containers"; continue }
  if ($en -eq 'docker') { $dockerOk = $true }
  Info $ev
  $images = Lines (Run $eng @('images', '--format', '{{.Repository}}:{{.Tag}}') 30) | Where-Object { $_ -and $_ -notmatch '<none>' } | Sort-Object -Unique
  if (-not $images) { Info "${en}: no local images" }
  foreach ($img in $images) {
    Probe "$en image $img" (Lines (Run $eng (@('run', '--rm', '--pull=never', '--entrypoint', 'sh', $img, '-c', $ImgSh, 'sh') + $Urls) 300)) "rebuild/pull $img with updated ca-certificates"
  }
  $running = @(Lines (Run $eng @('ps', '--format', '{{.Names}}|{{.Image}}') 30) | Where-Object { $_ })
  if (-not $running) { Info "${en}: no running containers" }
  foreach ($row in $running) {
    $name, $img = $row -split '\|', 2
    Probe "$en container $name ($img)" (Lines (Run $eng (@('exec', $name, 'sh', '-c', $ImgSh, 'sh') + $Urls) 300)) "rebuild $img with updated ca-certificates, then redeploy $name"
  }
}

Hdr 'WSL'
$wsl = Get-Command wsl.exe | Select-Object -First 1 -ExpandProperty Source
if (-not $wsl) { Info 'WSL not installed' }
else {
  $env:WSL_UTF8 = '1'
  $wv = (Run $wsl @('--version') 30)
  if ($wv.Code -ne 0 -or -not "$($wv.Out)".Trim()) { Warn 'inbox WSL (no --version support)' 'wsl --update' }
  else { Info ((Lines $wv | Where-Object { $_.Trim() } | Select-Object -First 3) -join '; ') }
  $cfg = "$env:USERPROFILE\.wslconfig"
  if (Test-Path $cfg) {
    $net = Get-Content $cfg | Where-Object { $_ -match '^\s*(networkingMode|autoProxy|dnsTunneling|firewall)\s*=' }
    Info ".wslconfig: $(if ($net) { ($net | ForEach-Object { $_.Trim() }) -join '; ' } else { 'no network settings' })"
  }
  Info 'WSL distros keep their own Linux CA store; Windows fixes do not apply inside them'
  $linuxScript = Join-Path $PSScriptRoot 'check-unix.sh'
  $distros = @(Lines (Run $wsl @('-l', '-v') 30) | ForEach-Object { $_ -replace "`0", '' } | Select-Object -Skip 1 | Where-Object { $_.Trim() } | ForEach-Object {
    $f = ($_ -replace '^\s*\*?\s*', '') -split '\s+'
    [pscustomobject]@{ Name = $f[0]; State = $f[1]; Version = $f[2] }
  })
  foreach ($d in $distros) {
    if ($d.Name -like 'docker-desktop*') { Info "$($d.Name): skipped (Docker Desktop internal)"; continue }
    Hdr "WSL distro: $($d.Name) (WSL$($d.Version), $($d.State))"
    if (Test-Path $linuxScript) {
      $p = (Run $wsl @('-d', $d.Name, '-e', 'wslpath', '-a', $linuxScript) 60).Out.Trim()
      $wslArgs = @('-d', $d.Name, '-e', 'bash', $p)
      if ($dockerOk) { $wslArgs += '--no-docker' }
      $r = Run $wsl $wslArgs 3600
      Lines $r | ForEach-Object { Write-Host "  $_" }
      switch ($r.Code) {
        0 { Ok "WSL $($d.Name): no issues" }
        1 {
          $fixCmd = if ($r.Out -match 'Fix commands') { "wsl -d $(Q $d.Name) -e bash $(Q $p) --fix$(if ($dockerOk) { ' --no-docker' }); if (`$LASTEXITCODE -notin 0, 1, 2) { throw ""WSL fix run failed (exit `$LASTEXITCODE)"" }; `$global:LASTEXITCODE = 0" }
          Fail "WSL $($d.Name): issues found (see its SUMMARY above)" "apply the manual steps listed for WSL $($d.Name) above" $fixCmd
        }
        2 { Warn "WSL $($d.Name): some checks not verified (see its SUMMARY above)" }
        default { Warn "WSL $($d.Name): check-unix.sh did not finish (code $($r.Code))" }
      }
    } else {
      Probe "WSL $($d.Name) default trust" (Lines (Run $wsl (@('-d', $d.Name, '-e', 'sh', '-c', $ImgSh, 'sh') + $Urls) 300)) 'inside distro: upgrade ca-certificates (apt/dnf/apk); full scan: put check-unix.sh next to this script'
    }
  }
}

Remove-Item -Recurse -Force $T

Hdr 'SUMMARY'
if ($Issues.Count -eq 0 -and $Untested.Count -eq 0) { Write-Host 'No issues found; all checks verified.' -ForegroundColor Green }
if ($Issues.Count -gt 0) {
  Write-Host "Issues ($($Issues.Count)):" -ForegroundColor Red
  $Issues | ForEach-Object { Write-Host "  - $_" }
}
if ($Cmds.Count -gt 0) {
  Write-Host "`nFix commands (run them, or re-run with -Fix):" -ForegroundColor Cyan
  for ($i = 0; $i -lt $Cmds.Count; $i++) { Write-Host "  cmd $($i + 1): $($Cmds[$i])" }
}
if ($Steps.Count -gt 0) {
  Write-Host "`nManual steps:" -ForegroundColor Cyan
  for ($i = 0; $i -lt $Steps.Count; $i++) { Write-Host "  step $($i + 1): $($Steps[$i])" }
}
if ($Untested.Count -gt 0) {
  Write-Host "`nNot verified ($($Untested.Count); fix network/tooling and re-run, or check by hand):" -ForegroundColor Yellow
  $Untested | ForEach-Object { Write-Host "  - $_" }
}
Write-Host "`nBrowsers are not tested: open each URL below in each browser; all $NT must show a certificate error."
$TestHosts | ForEach-Object { Write-Host "  https://$_-emudhra.we-have-a-problem.com/" }
Write-Host "`nNot scanned: project deps (rustls-webpki, webpki-roots, castore, composer/ca-bundle), Electron apps; images/containers/WSL fallback test only their first client (curl > wget > python3)."
if ($Fix -and $Cmds.Count -gt 0) {
  Hdr 'FIX'
  $fixFail = 0
  for ($i = 0; $i -lt $Cmds.Count; $i++) {
    Write-Host "`n+ cmd $($i + 1): $($Cmds[$i])"
    $global:LASTEXITCODE = 0
    try { Invoke-Expression $Cmds[$i]; $ok = $? -and $LASTEXITCODE -eq 0 } catch { $ok = $false }
    if ($ok) { Ok "cmd $($i + 1)" } else { Write-Host "[FAIL] cmd $($i + 1) (exit $LASTEXITCODE)" -ForegroundColor Red; $fixFail = 1 }
  }
  Write-Host "`nRe-run this script to verify the fixes."
}
if ($fixFail) { exit 3 }
if ($Issues.Count -gt 0) { exit 1 }
if ($Untested.Count -gt 0) { exit 2 }
exit 0
