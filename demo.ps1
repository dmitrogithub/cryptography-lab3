param([ValidateSet(1, 2, 3, 4)][int]$Mode = 1)
$ErrorActionPreference = 'Stop'
$executable = Join-Path $PSScriptRoot "bin\lab3-mode$Mode.exe"
if (!(Test-Path -LiteralPath $executable)) { throw 'Build the program with build.ps1 first.' }
$runName = 'run-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
$runDirectory = Join-Path $PSScriptRoot "examples\$runName"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$logPath = Join-Path $runDirectory 'demo-log.txt'
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($logPath, "DSTU 9212 mode=$Mode demo`r`n", $utf8)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
function Invoke-Lab3 {
    param([string[]]$CliArguments, [int]$ExpectedExit = 0)
    $line = 'lab3 ' + ($CliArguments -join ' ')
    Write-Host "`n> $line"
    [System.IO.File]::AppendAllText($logPath, "`r`n> $line`r`n", $utf8)
    # Native stderr is part of the expected INVALID example, not a script exception.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = & $executable @CliArguments 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    foreach ($item in $lines) {
        $text = $item.ToString()
        Write-Host $text
        [System.IO.File]::AppendAllText($logPath, "$text`r`n", $utf8)
    }
    [System.IO.File]::AppendAllText($logPath, "Exit code: $exitCode`r`n", $utf8)
    if ($exitCode -ne $ExpectedExit) { throw "Unexpected exit code $exitCode; expected $ExpectedExit." }
}
Push-Location -LiteralPath $runDirectory
try {
    [System.IO.File]::WriteAllText((Join-Path $runDirectory 'message.bin'), 'Laboratory 3: file signature example.', $utf8)
    Invoke-Lab3 -CliArguments @('--help')
    Invoke-Lab3 -CliArguments @('--command=generate', '--public-key=public.vpk', '--private-key=secret.vsk')
    Invoke-Lab3 -CliArguments @('--command=sign', '--file=message.bin', '--private-key=secret.vsk', '--type=detached', '--signing=deterministic', '--out=message.vsig')
    Invoke-Lab3 -CliArguments @('--command=verify', '--file=message.bin', '--public-key=public.vpk', '--type=detached', '--signature=message.vsig')
    Invoke-Lab3 -CliArguments @('--command=sign', '--file=message.bin', '--private-key=secret.vsk', '--type=detached', '--signing=randomized', '--out=message-random.vsig')
    Invoke-Lab3 -CliArguments @('--command=verify', '--file=message.bin', '--public-key=public.vpk', '--type=detached', '--signature=message-random.vsig')
    Invoke-Lab3 -CliArguments @('--command=sign', '--file=message.bin', '--private-key=secret.vsk', '--type=attached', '--signing=deterministic', '--out=message.vsigned')
    Invoke-Lab3 -CliArguments @('--command=verify', '--file=message.vsigned', '--public-key=public.vpk', '--type=attached', '--out=recovered.bin')
    $originalHash = (Get-FileHash -LiteralPath (Join-Path $runDirectory 'message.bin')).Hash
    $recoveredHash = (Get-FileHash -LiteralPath (Join-Path $runDirectory 'recovered.bin')).Hash
    if ($originalHash -ne $recoveredHash) { throw 'Recovered file differs from the original.' }
    Invoke-Lab3 -CliArguments @('--command=sign', '--file=message.bin', '--private-key=secret.vsk', '--type=attached', '--signing=randomized', '--out=message-random.vsigned')
    Invoke-Lab3 -CliArguments @('--command=verify', '--file=message-random.vsigned', '--public-key=public.vpk', '--type=attached')
    $changedBytes = [System.IO.File]::ReadAllBytes((Join-Path $runDirectory 'message.bin'))
    $changedBytes[0] = $changedBytes[0] -bxor 1
    [System.IO.File]::WriteAllBytes((Join-Path $runDirectory 'changed.bin'), $changedBytes)
    Invoke-Lab3 -CliArguments @('--command=verify', '--file=changed.bin', '--public-key=public.vpk', '--type=detached', '--signature=message.vsig') -ExpectedExit 1
    Write-Host "`nAll examples passed. Original and recovered bytes match."
    Write-Host "Files and log: $runDirectory"
    [System.IO.File]::AppendAllText($logPath, "`r`nAll examples passed; recovered file matches the original.`r`n", $utf8)
} finally { Pop-Location }
