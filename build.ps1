param([ValidateSet(1, 2, 3, 4)][int[]]$Mode = @(1, 2, 3, 4))
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$labRoot = Join-Path $projectRoot 'ЛР_3_ЕП_Вершина'
$vsLocator = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $vsLocator)) {
    throw 'Install Visual Studio Build Tools with the Desktop development with C++ component.'
}
$vsRoot = & $vsLocator -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vsRoot) {
    foreach ($candidate in (& $vsLocator -all -products '*' -property installationPath)) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'VC\Auxiliary\Build\vcvars64.bat')) {
            $vsRoot = $candidate
            break
        }
    }
}
if (!$vsRoot) { throw 'MSVC x64 tools were not found.' }
$vcSetup = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
# Import the compiler environment into this PowerShell process only.
$compilerEnvironment = & $env:ComSpec /d /s /c "call `"$vcSetup`" >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the MSVC environment.' }
foreach ($line in $compilerEnvironment) {
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) {
        [Environment]::SetEnvironmentVariable($line.Substring(0, $separator), $line.Substring($separator + 1), 'Process')
    }
}
$sources = @('api', 'convert', 'keygen', 'ntt_tables', 'poly', 'reduce', 'sign', 'tables', 'utils') |
    ForEach-Object { Join-Path $labRoot "library\src\$_.c" }
$sources += Join-Path $labRoot 'library\third_party\dstu7564\dstu7564.c'
$sources += Join-Path $labRoot 'library\third_party\dstu8845\dstu8845.c'
$sources += Join-Path $labRoot 'student\main.c'
$binDirectory = Join-Path $projectRoot 'bin'
New-Item -ItemType Directory -Path $binDirectory -Force | Out-Null
foreach ($selectedMode in ($Mode | Select-Object -Unique)) {
    $buildDirectory = Join-Path $projectRoot "build\windows\mode$selectedMode"
    New-Item -ItemType Directory -Path $buildDirectory -Force | Out-Null
    $executable = Join-Path $binDirectory "lab3-mode$selectedMode.exe"
    $compilerArgs = @('/nologo', '/TC', '/std:c11', '/utf-8', '/W4', '/O2', '/MT',
        '/D_CRT_SECURE_NO_WARNINGS', "/DDSTU9212_MODE=$selectedMode",
        "/I$labRoot\library\include", "/I$labRoot\library\third_party", "/I$labRoot\library\src")
    $compilerArgs += $sources
    $compilerArgs += @("/Fe:$executable", '/link', 'bcrypt.lib')
    Push-Location -LiteralPath $buildDirectory
    try {
        & cl.exe @compilerArgs
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for mode $selectedMode." }
    } finally { Pop-Location }
    if ($selectedMode -eq 1) {
        Copy-Item -LiteralPath $executable -Destination (Join-Path $binDirectory 'lab3.exe') -Force
    }
    Write-Output "Built: $executable"
}
Write-Output 'Done. Run .\bin\lab3.exe --help or .\RUN_DEMO.cmd.'
