<#
.SYNOPSIS
  eMudhra compromised-intermediate exposure check for Windows (plus WSL distros and Docker images).
  Ref: https://emudhra.we-have-a-problem.com/

.DESCRIPTION
  Usage:   powershell -ExecutionPolicy Bypass -File .\check-windows.ps1
  Method:  1) compare installed versions against the patched-version table
           2) live TLS test: each client connects to two test hosts signed by the
              compromised CAs. A patched client must REJECT them.
  Codes:   3 letters per client = test host 1, test host 2, control host (example.com)
           S = TLS accepted   C = certificate rejected   N = network/other error
           SS?/S??/?S? = trusts compromised CA (FAIL)   CCS = safe (OK)   other = inconclusive
  WSL:     each distro is scanned with check-linux.sh if it sits next to this script,
           else with a short built-in probe (curl/wget/python3 + ca-certificates version).
  Output:  [OK] / [INFO] / [WARN] / [FAIL] lines, then a SUMMARY with remediation steps.
#>

$ErrorActionPreference = 'SilentlyContinue'
$Ref = 'https://emudhra.we-have-a-problem.com/'
$Urls = 'https://dv-g3b-emudhra.we-have-a-problem.com/', 'https://dv-g3b-aaa-emudhra.we-have-a-problem.com/', 'https://example.com/'
$Issues = New-Object System.Collections.Generic.List[string]
$SeenBundles = @{}
$WinFix = "install Windows updates; else run Block-EmudhraCompromisedCA.ps1 elevated (see $Ref)"

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
function Fail($m, $fix) { Write-Host "[FAIL] $m" -ForegroundColor Red; $Issues.Add("$m -> $fix") }
function Warn($m, $fix) { Write-Host "[WARN] $m" -ForegroundColor Yellow; if ($fix) { $Issues.Add("$m -> $fix") } }
function Hdr($m) { Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Ver($text) { [regex]::Match("$text", '\d+(\.\d+)+').Value }
# Capture: run a native exe, return stdout+stderr as text (stderr is lost under SilentlyContinue)
function Capture($exe, [string[]]$arguments) { $ErrorActionPreference = 'Continue'; (& $exe @arguments 2>&1 | ForEach-Object { "$_" }) -join "`n" }
function Kv($lines, $key) { (@($lines) | Where-Object { "$_" -like "$key=*" } | Select-Object -First 1) -replace "^$key=", '' }

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

# Need: OK if version >= patch of its branch, or >= all patches
function Need($label, $v, $depth, $fix, [string[]]$patched) {
  $all = $true
  foreach ($p in $patched) {
    if (-not (VGe $v $p)) { $all = $false; continue }
    if ((Branch $v $depth) -eq (Branch $p $depth)) { Ok "$label $v"; return }
  }
  if ($all) { Ok "$label $v" } else { Fail "$label $v" "$fix (>= $($patched -join ' | '))" }
}

# One: single minimum version check for a tool on PATH
function One($name, $min, $fix, $exe, [string[]]$arguments) {
  $cmd = Get-Command $exe | Select-Object -First 1
  if (-not $cmd) { return }
  $v = Ver (Capture $cmd $arguments)
  if (-not $v) { Warn "${name}: version unknown"; return }
  if (VGe $v $min) { Ok "$name $v" } else { Fail "$name $v" "$fix (>= $min)" }
}

# Res: turn S/C/N codes into OK / FAIL / WARN
function Res($label, $codes, $fix) {
  $c = "$codes".Trim()
  if ($c -match '^(S..|.S.)$') { Fail "${label}: TRUSTS compromised CA [$c]" $fix }
  elseif ($c -eq 'CCS') { Ok "${label}: rejects compromised CA [$c]" }
  else { Warn "${label}: test inconclusive [$c]" }
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
    & $exe @extra -s -o NUL -m 15 $_ 2>$null
    if ($LASTEXITCODE -eq 0) { 'S' } elseif (35, 60, 77, 83, 91 -contains $LASTEXITCODE) { 'C' } else { 'N' }
  })
}

function GitCodes($exe) {
  $env:GIT_TERMINAL_PROMPT = '0'
  -join ($Urls | ForEach-Object {
    $e = Capture $exe @('-c', 'credential.helper=', 'ls-remote', $_)
    if ($LASTEXITCODE -eq 0) { 'S' }
    elseif ($e -match 'certificate|CERT_|revoked') { 'C' }
    elseif ($e -match 'not found|not valid|HTTP|returned error|Authentication|Username|repository') { 'S' }
    else { 'N' }
  })
}

function OpensslCodes($exe) {
  -join ($Urls | ForEach-Object {
    $h = ([uri]$_).Host
    $o = 'Q' | & $exe s_client -connect "${h}:443" -servername $h 2>&1 | Out-String
    if ($o -match 'Verify return code: 0 ') { 'S' } elseif ($o -match 'Verify return code: ') { 'C' } else { 'N' }
  })
}

# Windows trust (CryptoAPI chain engine + Disallowed store), as used by .NET / PowerShell / Schannel apps
function NetCodes {
  -join ($Urls | ForEach-Object {
    try {
      $r = [Net.WebRequest]::Create($_); $r.Timeout = 15000
      $r.GetResponse().Close(); 'S'
    } catch {
      $w = $_.Exception; while ($w.InnerException -and -not ($w -is [Net.WebException])) { $w = $w.InnerException }
      if ($w.Response) { 'S' } elseif ("$($w.Status) $($w.Message)" -match 'TrustFailure|SecureChannelFailure|certificate') { 'C' } else { 'N' }
    }
  })
}

# Bundle: live-test one PEM CA bundle file (once per path)
function Bundle($label, $file, $fix) {
  if (-not $file -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
  $key = (Get-Item -LiteralPath $file).FullName.ToLower()
  if ($SeenBundles[$key]) { return }
  $SeenBundles[$key] = 1
  if ($script:PyB) { Res "$label ($file)" (& $script:PyB "$T\probe.py" @Urls $file 2>$null) $fix }
  elseif ($script:GitCurl) { Res "$label ($file)" (CurlCodes $script:GitCurl @('--cacert', $file)) $fix }
  else { Info "$label ($file): no python/OpenSSL curl to test bundle" }
}

$T = Join-Path $env:TEMP ('emudhra-check-' + [guid]::NewGuid())
New-Item -ItemType Directory $T | Out-Null

Set-Content -Encoding ASCII "$T\probe.py" @'
import os, sys, ssl
try:
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    print("ver=" + sys.version.split()[0]); sys.exit()
URLS = sys.argv[1:4]
def codes(cafile=None):
    out = ""
    for u in URLS:
        try:
            urlopen(u, timeout=15, context=ssl.create_default_context(cafile=cafile)); out += "S"
        except HTTPError:
            out += "S"
        except Exception as e:
            out += "C" if "CERTIFICATE_VERIFY_FAILED" in str(getattr(e, "reason", e)) else "N"
    return out
if len(sys.argv) > 4:
    print(codes(sys.argv[4])); sys.exit()
print("ver=" + sys.version.split()[0])
print("exe=" + os.path.realpath(sys.executable))
print("sys=" + codes())
for key, mod in (("certifi", "certifi"), ("pipcertifi", "pip._vendor.certifi")):
    try:
        m = __import__(mod, fromlist=["where"])
        print("%s=%s|%s|%s" % (key, getattr(m, "__version__", "?"), m.where(), codes(m.where())))
    except Exception:
        pass
try:
    import pip; print("pip=" + pip.__version__)
except Exception:
    pass
'@

Set-Content -Encoding ASCII "$T\probe.js" @'
const https = require('https');
const urls = process.argv.slice(2), out = urls.map(() => 'N');
let left = urls.length;
urls.forEach((u, i) => {
  let done = false;
  const fin = c => { if (done) return; done = true; out[i] = c; if (--left === 0) { console.log(out.join('')); process.exit(0); } };
  const req = https.get(u, { timeout: 15000 }, r => { r.resume(); fin('S'); });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => fin(/CERT|SELF_SIGNED|UNABLE_TO|unable to verify|revoked/i.test(e.code + ' ' + e.message) ? 'C' : 'N'));
});
'@

# Runs inside each docker image / WSL distro with: sh -c $ImgSh sh URL1 URL2 CONTROL
# (no double quotes inside: Windows PowerShell 5.1 would mangle them when passing to native exes)
$ImgSh = @'
t(){ if command -v curl >/dev/null 2>&1; then curl -s -o /dev/null -m 15 $1; case $? in 0) printf S;; 35|60|77|83|91) printf C;; *) printf N;; esac; elif command -v wget >/dev/null 2>&1; then e=$(wget -q -T 15 -O /dev/null $1 2>&1); c=$?; if [ $c = 0 ] || [ $c = 8 ]; then printf S; elif [ $c = 5 ] || echo $e | grep -qi certificate; then printf C; else printf N; fi; elif command -v python3 >/dev/null 2>&1; then e=$(python3 -c 'import sys,urllib.request as u;u.urlopen(sys.argv[1],timeout=15)' $1 2>&1); c=$?; if [ $c = 0 ] || echo $e | grep -q HTTPError; then printf S; elif echo $e | grep -q CERTIFICATE_VERIFY_FAILED; then printf C; else printf N; fi; else printf X; fi; }; for u in $1 $2 $3; do t $u; done; echo; (dpkg-query -W -f='${Version}' ca-certificates || apk info -v ca-certificates || rpm -q ca-certificates) 2>/dev/null | head -1
'@

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

Write-Host "eMudhra CA exposure check (Windows) - ref: $Ref"
Write-Host 'Codes: S=TLS accepted, C=cert rejected, N=net error; order: test1, test2, control'

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

$GitCurl = Cands @() @("$env:ProgramFiles\Git\mingw64\bin\curl.exe") | Select-Object -First 1

Hdr 'curl'
foreach ($c in (Cands @('curl.exe') @("$env:SystemRoot\System32\curl.exe", "$env:ProgramFiles\Git\mingw64\bin\curl.exe"))) {
  Info "$((& $c --version 2>$null | Select-Object -First 1)) ($c)"
  $fix = if ($c -like "$env:SystemRoot\*") { $WinFix } else { 'update this curl / its CA bundle (Git for Windows: update Git)' }
  Res "curl ($c)" (CurlCodes $c @()) $fix
  Bundle 'curl bundle' (Join-Path (Split-Path $c) 'curl-ca-bundle.crt') 'replace curl-ca-bundle.crt with a patched bundle'
}

Hdr 'git'
foreach ($g in (Cands @('git.exe') @("$env:ProgramFiles\Git\cmd\git.exe"))) {
  $backend = & $g config --get http.sslBackend
  Info "$(& $g --version) ($g) sslBackend=$(if ($backend) { $backend } else { 'default' })"
  Res "git ls-remote ($g)" (GitCodes $g) 'update Git for Windows; or: git config --global http.sslBackend schannel'
}

Hdr 'openssl'
foreach ($o in (Cands @('openssl.exe') @("$env:ProgramFiles\Git\usr\bin\openssl.exe", "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe"))) {
  Info "$(& $o version 2>$null) ($o)"
  $fix = if ($o -like '*\Git\*') { 'update Git for Windows (bundled ca-bundle.crt)' } else { 'update the CA bundle this openssl uses' }
  Res "openssl s_client ($o)" (OpensslCodes $o) $fix
}

Hdr 'Python / pip / certifi'
$pyLauncher = @(& py -0p 2>$null | ForEach-Object { [regex]::Match("$_", '[A-Za-z]:\\.+?\.exe').Value } | Where-Object { $_ })
$pyGlobs = @(
  "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe", "$env:ProgramFiles\Python*\python.exe", 'C:\Python*\python.exe',
  "$env:APPDATA\uv\python\*\python.exe", "$env:USERPROFILE\.pyenv\pyenv-win\versions\*\python.exe",
  "$env:LOCALAPPDATA\mise\installs\python\*\python.exe"
) + @(foreach ($base in "$env:USERPROFILE\miniconda3", "$env:USERPROFILE\anaconda3", "$env:USERPROFILE\miniforge3", "$env:ProgramData\miniconda3", "$env:ProgramData\anaconda3") {
  "$base\python.exe"; "$base\envs\*\python.exe"
}) + $pyLauncher
$pySeen = @{}
foreach ($py in (Cands @('python.exe', 'python3.exe') $pyGlobs)) {
  $out = @(& $py "$T\probe.py" @Urls 2>$null)
  $v = Kv $out 'ver'
  if (-not $v) { if ($py -notlike '*\WindowsApps\*') { Warn "python ($py): did not run" }; continue }
  $exe = (Kv $out 'exe').ToLower()
  if ($pySeen[$exe]) { continue }
  $pySeen[$exe] = 1
  if (-not (Kv $out 'sys')) { Info "python $v ($py): too old to test"; continue }
  if (-not $script:PyB) { $script:PyB = $py }
  $pipfix = "& '$py' -m pip install -U pip certifi"
  Res "python $v ($py) default trust (Windows Root store, ignores Disallowed)" (Kv $out 'sys') 'pip install -U certifi truststore and use truststore (honors Disallowed); or set SSL_CERT_FILE to a patched certifi bundle'
  $c = Kv $out 'certifi'
  if ($c) {
    $cv, $cp, $cc = $c -split '\|'
    if (VGe $cv '2026.10.19') { Ok "certifi $cv ($cp)" } else { Fail "certifi $cv ($cp)" "$pipfix (certifi >= 2026.10.19)" }
    Res "certifi bundle ($cp)" $cc $pipfix
    $SeenBundles[$cp.ToLower()] = 1
  }
  $pv = Kv $out 'pip'
  if ($pv) { if (VGe $pv '26.2.2') { Ok "pip $pv ($py)" } else { Fail "pip $pv ($py)" "$pipfix (pip >= 26.2.2)" } }
  $c = Kv $out 'pipcertifi'
  if ($c) { $cv, $cp, $cc = $c -split '\|'; Res "pip vendored certifi $cv" $cc $pipfix }
}

Hdr 'Bundles shipped with Git for Windows'
foreach ($f in "$env:ProgramFiles\Git\mingw64\etc\ssl\certs\ca-bundle.crt", "$env:ProgramFiles\Git\mingw64\ssl\certs\ca-bundle.crt", "$env:ProgramFiles\Git\usr\ssl\certs\ca-bundle.crt") { Bundle 'Git bundle (used when sslBackend=openssl)' $f 'update Git for Windows; or: git config --global http.sslBackend schannel' }

Hdr 'Node.js / npm'
$nodeGlobs = "$env:ProgramFiles\nodejs\node.exe", "$env:NVM_HOME\v*\node.exe", "$env:APPDATA\nvm\v*\node.exe",
  "$env:LOCALAPPDATA\Volta\tools\image\node\*\node.exe", "$env:APPDATA\fnm\node-versions\*\installation\node.exe",
  "$env:LOCALAPPDATA\mise\installs\node\*\node.exe"
foreach ($n in (Cands @('node.exe') $nodeGlobs)) {
  $v = & $n -v 2>$null
  if (-not $v) { continue }
  Need "node ($n)" $v 1 'upgrade Node.js' @('22.23.4', '24.22.1', '26.12.1')
  Res "node $v ($n)" (& $n "$T\probe.js" @Urls 2>$null) 'upgrade Node.js to a patched release'
  $npm = Join-Path (Split-Path $n) 'npm.cmd'
  if (Test-Path $npm) { Info "npm $(& $npm -v 2>$null) ($npm)" }
}

Hdr 'Java'
$javaGlobs = "$env:JAVA_HOME\bin\java.exe", "$env:ProgramFiles\Java\*\bin\java.exe", "${env:ProgramFiles(x86)}\Java\*\bin\java.exe",
  "$env:ProgramFiles\Eclipse Adoptium\*\bin\java.exe", "$env:ProgramFiles\Microsoft\jdk-*\bin\java.exe", "$env:ProgramFiles\Zulu\*\bin\java.exe",
  "$env:ProgramFiles\Amazon Corretto\*\bin\java.exe", "$env:ProgramFiles\BellSoft\*\bin\java.exe", "$env:USERPROFILE\.jdks\*\bin\java.exe"
foreach ($j in (Cands @('java.exe') $javaGlobs)) {
  $jv = [regex]::Match((Capture $j @('-version')), 'version "([^"]+)"').Groups[1].Value
  if ($jv -like '1.*') { $jv = $jv.Substring(2) -replace '_', '.' }
  if ($jv) { Need "java ($j)" $jv 1 'upgrade JDK' @('27.0.1.0.2', '25.0.5.0.2', '21.0.13.0.2', '17.0.21.0.2', '11.0.33.0.2', '8.0.511') }
}

Hdr 'Go'
foreach ($g in (Cands @('go.exe') @("$env:ProgramFiles\Go\bin\go.exe", "$env:USERPROFILE\sdk\go*\bin\go.exe"))) {
  Need "go ($g)" (Ver (& $g version)) 2 'upgrade Go' @('1.27.3', '1.26.10')
}

Hdr 'Other tools'
One 'uv' '0.13.4' 'uv self update' 'uv' @('--version')
One 'pixi' '0.82.1' 'pixi self-update' 'pixi' @('--version')
One 'rustup' '1.29.2' 'rustup self update' 'rustup' @('--version')
One 'deno' '2.9.8' 'deno upgrade' 'deno' @('--version')
One 'mise' '2026.10.17' 'mise self-update' 'mise' @('--version')
One 'claude code' '2.1.303' 'claude update' 'claude' @('--version')
if (Get-Command electron) { Need 'electron' (Ver (Capture 'electron' @('--version'))) 1 'upgrade Electron' @('44.9.1', '43.8.1', '42.11.16') }
if (Get-Command bun) { Warn "bun $(& bun --version): vendor fix pending" "watch $Ref; avoid bun for TLS to untrusted hosts" }
if (Get-Command perl) {
  $pv = & perl -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>$null
  if ($pv) { if (VGe $pv '20261020') { Ok "perl Mozilla::CA $pv" } else { Fail "perl Mozilla::CA $pv" 'cpan Mozilla::CA (>= 20261020)' } }
}

Hdr 'Env / config'
foreach ($e in 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'PIP_CERT', 'NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO', 'HTTPS_PROXY') {
  $v = [Environment]::GetEnvironmentVariable($e)
  if ($v) {
    Info "$e=$v"
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
  if ((& git config --get http.sslVerify) -eq 'false') { Fail 'git http.sslVerify=false' 'git config --global --unset http.sslVerify' }
  $c = & git config --get http.sslCAInfo
  if ($c) { Bundle 'git http.sslCAInfo' $c 'update Git for Windows; or: git config --global http.sslBackend schannel' }
}
if (Get-Command npm) {
  if ((& npm config get strict-ssl 2>$null) -eq 'false') { Fail 'npm strict-ssl=false' 'npm config set strict-ssl true' }
  $c = & npm config get cafile 2>$null
  if ($c -and $c -notin 'null', 'undefined') { Bundle 'npm cafile' $c 'update npm cafile bundle' }
}
if ($PyB) {
  $pc = & $PyB -m pip config list 2>$null
  $c = [regex]::Match(($pc | Out-String), "\.cert='([^']+)'").Groups[1].Value
  if ($c) { Bundle 'pip config cert' $c 'update pip cert bundle' }
  if ($pc -match 'trusted-host') { Warn 'pip trusted-host set (TLS verify off for those hosts)' 'remove trusted-host from pip config' }
}

Hdr 'Browsers'
$browsers = [ordered]@{
  'Chrome'  = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
  'Edge'    = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
  'Firefox' = "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
  'Brave'   = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
  'Opera'   = "$env:LOCALAPPDATA\Programs\Opera\opera.exe"
  'Vivaldi' = "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe"
}
foreach ($b in $browsers.Keys) {
  foreach ($p in $browsers[$b]) { if (Test-Path $p) { Info "$b $((Get-Item $p).VersionInfo.ProductVersion) ($p)" } }
}

Hdr 'Docker'
$dockerOk = $false
if (-not (Get-Command docker)) { Info 'docker not installed' }
else {
  $sv = & docker version --format '{{.Server.Version}}' 2>$null
  $ostype = & docker info --format '{{.OSType}}' 2>$null
  if (-not $sv) { Warn 'docker daemon not reachable; images not checked' 'start Docker Desktop and re-run' }
  elseif ($ostype -ne 'linux') { Info "docker server $sv in $ostype-container mode; image test needs Linux containers" }
  else {
    $dockerOk = $true
    Info "docker client $(& docker version --format '{{.Client.Version}}'), server $sv"
    $images = & docker images --format '{{.Repository}}:{{.Tag}}' | Where-Object { $_ -notmatch '<none>' } | Sort-Object -Unique
    foreach ($img in $images) {
      $o = @(& docker run --rm --pull=never --entrypoint sh $img -c $ImgSh sh @Urls 2>$null)
      $codes = "$($o[0])"; $pkg = "$($o[1])"
      if (-not $codes) { Warn "image ${img}: cannot run sh (distroless/other arch)" }
      elseif ($codes -match 'X') { Info "image ${img}: no curl/wget/python3 to test; ca-certificates $pkg" }
      else { Res "image $img [ca-certificates $pkg]" $codes "rebuild/pull $img with updated ca-certificates" }
    }
  }
}

Hdr 'WSL'
if (-not (Get-Command wsl.exe)) { Info 'WSL not installed' }
else {
  $env:WSL_UTF8 = '1'
  $wv = (& wsl.exe --version 2>$null | Out-String) -replace "`0", ''
  if ($LASTEXITCODE -ne 0 -or -not $wv.Trim()) { Warn 'inbox WSL (no --version support)' 'wsl --update' }
  else { Info ((($wv -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3) -join '; ') }
  $cfg = "$env:USERPROFILE\.wslconfig"
  if (Test-Path $cfg) {
    $net = Get-Content $cfg | Where-Object { $_ -match '^\s*(networkingMode|autoProxy|dnsTunneling|firewall)\s*=' }
    Info ".wslconfig: $(if ($net) { ($net | ForEach-Object { $_.Trim() }) -join '; ' } else { 'no network settings' })"
  }
  Info 'WSL distros keep their own Linux CA store; Windows fixes do not apply inside them'
  $linuxScript = Join-Path $PSScriptRoot 'check-linux.sh'
  $distros = @(& wsl.exe -l -v 2>$null | ForEach-Object { $_ -replace "`0", '' } | Select-Object -Skip 1 | Where-Object { $_.Trim() } | ForEach-Object {
    $f = ($_ -replace '^\s*\*?\s*', '') -split '\s+'
    [pscustomobject]@{ Name = $f[0]; State = $f[1]; Version = $f[2] }
  })
  foreach ($d in $distros) {
    if ($d.Name -like 'docker-desktop*') { Info "$($d.Name): skipped (Docker Desktop internal)"; continue }
    Hdr "WSL distro: $($d.Name) (WSL$($d.Version), $($d.State))"
    if (Test-Path $linuxScript) {
      $p = (& wsl.exe -d $d.Name -e wslpath -a $linuxScript | Out-String).Trim()
      $wslArgs = @('-d', $d.Name, '-e', 'bash', $p)
      if ($dockerOk) { $wslArgs += '--no-docker' }
      $o = @(& wsl.exe @wslArgs 2>&1)
      $o | ForEach-Object { Write-Host "  $_" }
      if ($o -match '^\[FAIL\]') { Fail "WSL $($d.Name): issues found (see its SUMMARY above)" 'apply the fixes listed inside that distro' }
    } else {
      $o = @(& wsl.exe -d $d.Name -e sh -c $ImgSh sh @Urls 2>$null)
      $codes = "$($o[0])"; $pkg = "$($o[1])"
      if ($codes -match 'X' -or -not $codes) { Info "no curl/wget/python3 to test; ca-certificates $pkg" }
      else { Res "WSL $($d.Name) default trust [ca-certificates $pkg]" $codes 'inside distro: upgrade ca-certificates (apt/dnf/apk); full scan: put check-linux.sh next to this script' }
    }
  }
}

Remove-Item -Recurse -Force $T

Hdr 'SUMMARY'
if ($Issues.Count -eq 0) { Write-Host 'No issues found.' -ForegroundColor Green }
else {
  Write-Host "$($Issues.Count) issue(s):" -ForegroundColor Red
  $Issues | ForEach-Object { Write-Host " - $_" }
}
Write-Host "Manual: open $($Urls[0]) and $($Urls[1]) in each browser; each must show a certificate error."
Write-Host 'Not scanned: project deps (rustls-webpki, webpki-roots, castore, composer/ca-bundle), Electron apps.'
