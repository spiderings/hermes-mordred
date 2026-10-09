[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$Python = 'python',
    [switch]$OwnedInstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$temporary = $null
try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Windows is required.' }
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    # A pwsh -> Python -> powershell.exe chain can inherit PS7 module paths.
    # Resolve built-in modules from THIS runtime, not that inherited search path.
    foreach ($module in @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')) {
        $manifest = [IO.Path]::Combine($PSHOME, 'Modules', $module, "$module.psd1")
        Import-Module -Name $manifest -Force -ErrorAction Stop
    }
    if (-not $InstallDir) {
        # ASCII JSON preserves Unicode paths across Python/PowerShell code pages.
        $resolve = "import json; from mordred_hermes._home import hermes_home; print(json.dumps(str(hermes_home().joinpath('bin'))))"
        $resolved = @(& $Python -c $resolve)
        if ($LASTEXITCODE -ne 0 -or $resolved.Count -ne 1) { throw 'Cannot resolve the Hermes home with the selected Python.' }
        $InstallDir = [string]($resolved[0] | ConvertFrom-Json)
    }
    # IsPathRooted also accepts C:relative and \relative. PowerShell 5.1's
    # .NET Framework lacks IsPathFullyQualified, so require a drive root or
    # a complete UNC server/share root before resolving the full path.
    $root = [IO.Path]::GetPathRoot($InstallDir)
    $driveRoot = $root -match '^[A-Za-z]:[\\/]$'
    $uncRoot = $root -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+[\\/]?$'
    if (-not ($driveRoot -or $uncRoot)) { throw 'InstallDir must be an absolute path.' }
    $InstallDir = [IO.Path]::GetFullPath($InstallDir)
    $version = @(& rustc -vV)
    if ($LASTEXITCODE -ne 0) { throw 'rustc failed. Install the Rust MSVC toolchain and Visual C++ build tools.' }
    $hostLine = @($version | Where-Object { $_ -match '^host: .+-pc-windows-msvc$' })
    if ($hostLine.Count -ne 1) { throw 'A native Windows MSVC Rust toolchain is required.' }
    $target = $hostLine[0].Substring(6)
    $targetDir = Join-Path $PSScriptRoot 'target'
    & cargo build --release --locked --manifest-path (Join-Path $PSScriptRoot 'Cargo.toml') --target $target --target-dir $targetDir
    if ($LASTEXITCODE -ne 0) { throw 'Cargo build failed; the installed helper has not been changed.' }
    $name = 'mordred-hermes-winkey.exe'
    $built = Join-Path $targetDir "$target\release\$name"
    $stream = [IO.File]::OpenRead($built)
    try {
        if ($stream.ReadByte() -ne 0x4d -or $stream.ReadByte() -ne 0x5a) { throw 'Build output is not a Windows executable.' }
    } finally { $stream.Dispose() }
    $expected = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash
    if ($OwnedInstall) {
        # The installed package owns publication and refuses unknown/reparse destinations.
        $publishArgs = @('-m', 'mordred_hermes.wizard._windows_install', 'helper', $built, $InstallDir, '--expected-sha256', $expected)
        & $Python @publishArgs
        if ($LASTEXITCODE -ne 0) { throw 'Helper publication failed; no verified installation is claimed.' }
        $destination = Join-Path $InstallDir $name
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $expected) { throw 'Installed helper hash mismatch.' }
    } else {
        [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
        $destination = Join-Path $InstallDir $name
        $temporary = Join-Path $InstallDir ('.winkey-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        [IO.File]::Copy($built, $temporary, $false)
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $expected) { throw 'Copied helper hash mismatch.' }
        if ([IO.File]::Exists($destination)) {
            # Refuse a mapped/in-use binary before replacement. File.Replace is atomic;
            # a concurrent opener or a failed replacement leaves the old file intact.
            $exclusive = [IO.File]::Open($destination, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $exclusive.Dispose()
            # PowerShell 5.1 coerces untyped $null to an empty string here.
            [IO.File]::Replace($temporary, $destination, [NullString]::Value)
        } else {
            [IO.File]::Move($temporary, $destination)
        }
        $temporary = $null
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $expected) { throw 'Installed helper hash mismatch.' }
    }
    Write-Output "Installed: $destination"
    Write-Output "SHA256: $expected"
    Write-Output 'Build/install only: TPM readiness requires an explicit live probe under the intended user logon.'
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
} finally {
    if ($temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
