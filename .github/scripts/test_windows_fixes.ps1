# Exercise fix planning/execution without scanning the host or updating installed tools.
$ErrorActionPreference = 'Stop'
$scanner = Join-Path $PSScriptRoot '..\..\check-windows.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scanner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
  ForEach-Object { Invoke-Expression $_.Extent.Text }

$script:TestCount = 0
function AssertEqual($label, $actual, $expected) {
  if ($actual -cne $expected) { throw "${label}: expected [$expected], got [$actual]" }
  $script:TestCount++
}
function Fixture($relative, $text = '') {
  $path = Join-Path $testRoot $relative
  [IO.Directory]::CreateDirectory((Split-Path $path)) | Out-Null
  [IO.File]::WriteAllText($path, $text)
  $path
}

$testRoot = Join-Path $PSScriptRoot ('.windows-fix-tests-' + [guid]::NewGuid())
$envNames = 'USERPROFILE', 'ProgramData', 'SCOOP', 'SCOOP_GLOBAL', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'PIPX_HOME', 'PATH'
$savedEnv = @{}
foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
  $env:USERPROFILE = Join-Path $testRoot 'profile'
  $env:ProgramData = Join-Path $testRoot 'program-data'
  $env:LOCALAPPDATA = Join-Path $testRoot 'local-data'
  foreach ($name in 'SCOOP', 'SCOOP_GLOBAL', 'XDG_CONFIG_HOME') {
    [Environment]::SetEnvironmentVariable($name, $null)
  }
  $ToolFix = @{}
  $scoopCommand = Fixture 'profile\scoop\shims\scoop.ps1'
  $env:PATH = (Split-Path $scoopCommand) + ';' + $savedEnv['PATH']

  $userScoop = Fixture 'profile\scoop\apps\uv\current\uv.exe'
  $globalScoop = Fixture 'program-data\scoop\apps\uv\current\uv.exe'
  AssertEqual 'user Scoop scope' (UpCmd $userScoop 'self update') "scoop update 'uv'"
  AssertEqual 'global Scoop scope' (UpCmd $globalScoop 'self update') "scoop update --global 'uv'"
  $shim = Fixture 'program-data\scoop\shims\uv.exe'
  Fixture 'program-data\scoop\shims\uv.shim' ('path = "' + $globalScoop + '"') | Out-Null
  AssertEqual 'global Scoop shim scope' (UpCmd $shim 'self update') "scoop update --global 'uv'"
  $env:SCOOP = Join-Path $testRoot 'custom-user'
  $env:SCOOP_GLOBAL = Join-Path $testRoot 'custom-global'
  $customUser = Fixture 'custom-user\apps\uv\current\uv.exe'
  $customGlobal = Fixture 'custom-global\apps\uv\current\uv.exe'
  AssertEqual 'custom user Scoop root' (UpCmd $customUser 'self update') "scoop update 'uv'"
  AssertEqual 'custom global Scoop root' (UpCmd $customGlobal 'self update') "scoop update --global 'uv'"
  $unknown = Fixture 'unknown\scoop\apps\uv\current\uv.exe'
  AssertEqual 'unknown Scoop root stays manual' (UpCmd $unknown 'self update') ''

  $env:SCOOP = $null; $env:SCOOP_GLOBAL = $null
  $config = @{ root_path = (Join-Path $testRoot 'configured-user'); global_path = (Join-Path $testRoot 'configured-global') }
  $configFile = Fixture 'profile\.config\scoop\config.json' ($config | ConvertTo-Json)
  $configuredUser = Fixture 'configured-user\apps\uv\current\uv.exe'
  $configuredGlobal = Fixture 'configured-global\apps\uv\current\uv.exe'
  AssertEqual 'configured Scoop user root' (UpCmd $configuredUser 'self update') "scoop update 'uv'"
  AssertEqual 'configured Scoop global root' (UpCmd $configuredGlobal 'self update') "scoop update --global 'uv'"
  AssertEqual 'stale default user Scoop root stays manual' (UpCmd $userScoop 'self update') ''
  AssertEqual 'stale default global Scoop root stays manual' (UpCmd $globalScoop 'self update') ''
  $env:SCOOP = Join-Path $testRoot 'custom-user'
  $env:SCOOP_GLOBAL = Join-Path $testRoot 'custom-global'
  AssertEqual 'Scoop user environment overrides config' (UpCmd $customUser 'self update') "scoop update 'uv'"
  AssertEqual 'Scoop global environment overrides config' (UpCmd $customGlobal 'self update') "scoop update --global 'uv'"
  $env:SCOOP = $null; $env:SCOOP_GLOBAL = $null
  $scoopCommand = Fixture 'portable\shims\scoop.ps1'
  $env:PATH = (Split-Path $scoopCommand) + ';' + $savedEnv['PATH']
  $portable = Fixture 'portable\apps\uv\current\uv.exe'
  Fixture 'portable\config.json' '{}' | Out-Null
  AssertEqual 'portable config overrides user config' (UpCmd $portable 'self update') "scoop update 'uv'"
  AssertEqual 'inactive configured Scoop root stays manual' (UpCmd $configuredUser 'self update') ''
  [IO.File]::WriteAllText((Join-Path $testRoot 'portable\config.json'), '{bad json')
  AssertEqual 'malformed Scoop config stays manual' (UpCmd $portable 'self update') ''
  [IO.File]::WriteAllText((Join-Path $testRoot 'portable\config.json'), '{}')

  $export = Fixture 'profile\.local\bin\uv.exe'
  $managed = Fixture 'local-data\uv\tools\uv\Scripts\uv.exe'
  $ToolFix[$managed] = "uv tool upgrade 'uv'"
  AssertEqual 'unidentified uv export stays manual' (UpCmd $export 'self update') ''
  AssertEqual 'managed uv retains its owner command' (UpCmd $managed 'self update') "uv tool upgrade 'uv'"

  AssertEqual 'successful PowerShell fix' (InvokeFix 'Write-Output "simulated successful fix"').Ok $true
  $ErrorActionPreference = 'SilentlyContinue'
  try {
    $result = InvokeFix 'Write-Error "simulated nonterminating error"; Write-Output "must not mask failure"'
    $afterPreference = $ErrorActionPreference
  } finally { $ErrorActionPreference = 'Stop' }
  AssertEqual 'PowerShell error fails fix' $result.Ok $false
  AssertEqual 'fix error is retained' $result.Error 'simulated nonterminating error'
  AssertEqual 'terminating error fails fix' (InvokeFix 'throw "simulated exception"').Ok $false
  AssertEqual 'fix runner preserves caller preference' $afterPreference 'SilentlyContinue'
  $shell = (Get-Process -Id $PID).Path
  $result = InvokeFix "& $(Q $shell) -NoProfile -NonInteractive -Command 'exit 9'"
  AssertEqual 'native nonzero exit fails fix' $result.Ok $false
  AssertEqual 'native failure exit code retained' $result.Code 9
  AssertEqual 'native zero exit succeeds' (InvokeFix "& $(Q $shell) -NoProfile -NonInteractive -Command 'exit 0'").Ok $true

  $env:PIPX_HOME = 'original-pipx-home'
  function pipx { Write-Error 'simulated pipx failure' }
  $pipxFix = PipxCmd (Join-Path $testRoot 'pipx\venvs\uv') 'upgrade-shared'
  AssertEqual 'pipx PowerShell error fails fix' (InvokeFix $pipxFix).Ok $false
  AssertEqual 'pipx home restored after failure' $env:PIPX_HOME 'original-pipx-home'

  # Run the real final fix loop and exit handling in a child process, with an inert failing command.
  $source = [IO.File]::ReadAllText($scanner)
  $tail = $source.Substring($source.LastIndexOf('if ($Fix -and $Cmds.Count -gt 0)'))
  $definitions = ($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { $_.Extent.Text }) -join "`n"
  $setup = '$ErrorActionPreference = ''SilentlyContinue''; $Fix = $true; $Cmds = @(''Write-Error "simulated fix failure"; Write-Output "later success"''); $Issues = @(); $Untested = @()'
  $scenario = Fixture 'fix-exit.ps1' ($definitions + "`n" + $setup + "`n" + $tail)
  $output = & $shell -NoProfile -NonInteractive -File $scenario 2>&1
  AssertEqual 'fix loop exits 3 on PowerShell error' $LASTEXITCODE 3
  AssertEqual 'fix loop does not print success for failed command' ([bool]($output -match '\[OK\].*cmd 1')) $false
  Write-Host "Passed $script:TestCount Windows fix regression checks (PowerShell $($PSVersionTable.PSVersion))."
} finally {
  foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) }
  $fullRoot = [IO.Path]::GetFullPath($testRoot)
  $expectedPrefix = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\.windows-fix-tests-'
  if (-not $fullRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected test cleanup path' }
  if (Test-Path -LiteralPath $fullRoot) { Remove-Item -LiteralPath $fullRoot -Recurse -Force }
}
