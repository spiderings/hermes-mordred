# Native Windows installation into the actual Hermes environment. No Bash/WSL.
[CmdletBinding()]
param(
    [string]$Python = $env:MORDRED_HERMES_PYTHON,
    [string]$Uv = $env:MORDRED_HERMES_UV,
    [string]$Version,
    [string]$Source,
    [switch]$InstallOnly,
    [ValidateSet('install', 'configure', 'setup', 'uninstall')][string]$Action = 'install',
    [string[]]$CommandArgs = @()
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$constraints = $null
$cliCode = 'from mordred_hermes.wizard.cli import main; raise SystemExit(main())'
function Invoke-Native {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Native command failed (exit $LASTEXITCODE): $Executable" }
}
function Read-PythonJson {
    param([string]$Interpreter, [string]$Code, [string[]]$Arguments = @())
    $lines = @(Invoke-Native $Interpreter (@('-c', $Code) + $Arguments))
    if ($lines.Count -ne 1) { throw 'Selected Python returned ambiguous output.' }
    return ($lines[0] | ConvertFrom-Json)
}
function Test-Python {
    param([string]$Candidate)
    $code = @'
import importlib.metadata as m, json, os, sys
import hermes_cli
from packaging.version import Version
p = sys.prefix
venv = sys.prefix != sys.base_prefix or os.path.isdir(os.path.join(p, 'conda-meta'))
d = m.distribution('hermes-agent')
ok = venv and Version(d.version) >= Version('0.13.0') and any(e.group == 'console_scripts' and e.name == 'hermes' for e in d.entry_points)
print(json.dumps(dict(ok=ok, python=sys.executable, root=p, version=d.version)))
'@
    $data = Read-PythonJson $Candidate $code
    if (-not $data.ok -or -not [string]::Equals([IO.Path]::GetFullPath($Candidate), [IO.Path]::GetFullPath($data.python), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Selected Python is not the actual Hermes virtualenv/conda interpreter (Hermes >=0.13 required).'
    }
    return $data
}
function Find-Python {
    param([string]$HomePath)
    if ($Python) { return (Test-Python ([IO.Path]::GetFullPath($Python))) }
    $launcher = Get-Command hermes.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($launcher) { $launcherPath = $launcher.Source }
    else {
        $launcherPath = Join-Path $HomePath 'hermes-agent\.hermes\bin\hermes.exe'
        if (-not [IO.File]::Exists($launcherPath)) { $launcherPath = $null }
    }
    $candidates = @()
    if ($launcherPath) {
        $parent = [IO.Path]::GetDirectoryName($launcherPath)
        $candidates += Join-Path $parent 'python.exe'
        $candidates += Join-Path ([IO.Path]::GetDirectoryName($parent)) 'python.exe'
        foreach ($candidate in $candidates) {
            if ([IO.File]::Exists($candidate)) { return (Test-Python $candidate) }
        }
        # Desktop launcher answers using its own managed environment. A supplied
        # launcher never falls back to an unrelated canonical venv.
        $site = @(Invoke-Native $launcherPath @('--run-module', 'site'))
        foreach ($line in $site) {
            if ($line -match "['`"](.+?)[\\/]+Lib[\\/]+site-packages['`"]") {
                $root = $Matches[1].Replace('\\', '\')
                $candidate = Join-Path $root 'Scripts\python.exe'
                if ([IO.File]::Exists($candidate)) { return (Test-Python $candidate) }
                $candidate = Join-Path $root 'python.exe'
                if ([IO.File]::Exists($candidate)) { return (Test-Python $candidate) }
            }
        }
        throw 'Could not resolve the actual Hermes launcher environment; pass -Python explicitly.'
    }
    foreach ($name in @('Scripts\python.exe', 'python.exe')) {
        $candidate = Join-Path (Join-Path $HomePath 'hermes-agent\venv') $name
        if ([IO.File]::Exists($candidate)) { return (Test-Python $candidate) }
    }
    throw 'Hermes environment not found. Install native Hermes first or pass -Python explicitly.'
}
try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'This installer requires native Windows.' }
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
    # Piped native Python otherwise defaults to the Windows ANSI code page.
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    foreach ($module in @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')) {
        Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules', $module, "$module.psd1")) -Force
    }
    # Do not let ambient Python/uv configuration redirect interpreter, sources,
    # package verification or installation location. Match install.sh isolation.
    $scrub = @('PYTHONHOME', 'PYTHONPATH', 'UV_PYTHON', 'UV_PROJECT_ENVIRONMENT',
        'UV_INDEX', 'UV_INDEX_URL', 'UV_DEFAULT_INDEX', 'UV_EXTRA_INDEX_URL', 'UV_FIND_LINKS',
        'UV_INDEX_STRATEGY', 'UV_NO_SOURCES', 'UV_OFFLINE', 'UV_CONFIG_FILE', 'UV_INSECURE_HOST',
        'UV_NO_VERIFY_HASHES', 'UV_SYSTEM_CERTS', 'UV_PRERELEASE', 'UV_EXCLUDE_NEWER',
        'UV_SYSTEM_PYTHON', 'UV_BREAK_SYSTEM_PACKAGES')
    foreach ($name in $scrub) {
        $environmentPath = 'Env:' + $name
        if (Test-Path -LiteralPath $environmentPath) {
            Remove-Item -LiteralPath $environmentPath -ErrorAction Stop
        }
    }
    $env:UV_NO_CONFIG = '1'
    $homePath = $env:HERMES_HOME
    if (-not $homePath) { $homePath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.hermes' }
    $selected = Find-Python $homePath
    $Python = [string]$selected.python
    # Use Hermes's profile-aware home resolution, not our bootstrap guess.
    $resolveHome = "import json; from hermes_constants import get_hermes_home; print(json.dumps(str(get_hermes_home())))"
    $homePath = [string](Read-PythonJson $Python $resolveHome)
    if ($InstallOnly -and $Action -ne 'install') { throw '-InstallOnly cannot claim configure/setup completion.' }
    if (-not $Uv) {
        $command = Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue
        if ($command) { $Uv = $command.Source }
        else {
            $bundled = @(Get-ChildItem -LiteralPath (Join-Path $homePath 'tools') -Filter 'uv-*' -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'uv.exe' } | Where-Object { [IO.File]::Exists($_) } | Sort-Object)
            if ($bundled.Count) { $Uv = $bundled[-1] }
        }
    }
    if (-not $Uv) { throw 'uv.exe not found; install uv or pass -Uv.' }
    $uvItem = Get-Item -LiteralPath $Uv -ErrorAction Stop
    if ($uvItem.PSIsContainer -or [IO.Path]::GetExtension($uvItem.FullName) -ine '.exe') {
        throw 'Selected uv must be a native executable file.'
    }
    $Uv = $uvItem.FullName
    # The delegated CLI must target these validated selections, even when PATH,
    # the profile venv or inherited resolver overrides name another environment.
    $env:MORDRED_HERMES_PYTHON = $Python
    $env:MORDRED_HERMES_UV = $Uv
    if ($Action -eq 'uninstall') {
        Invoke-Native $Python (@('-c', $cliCode, 'uninstall') + $CommandArgs)
        exit 0
    }
    if ($Source -and $Version) { throw 'Choose -Source or -Version, not both.' }
    if ($Source) {
        $resolvedSource = (Get-Item -LiteralPath $Source -ErrorAction Stop).FullName
        $package = "${resolvedSource}[keyvault,extension]"
    } elseif ($Version) {
        if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[ab]|rc)?[0-9]*(?:\.post[0-9]+)?$') { throw '-Version must be an exact release pin.' }
        $package = "hermes-mordred[keyvault,extension]==$Version,>=0.1.0a16"
    } else {
        throw 'Specify an exact -Version release pin or -Source checkout/wheel. Unpublished port acceptance requires -Source.'
    }
    # Snapshot installed pins before changing Mordred; never re-resolve Hermes.
    $constraints = [IO.Path]::GetTempFileName()
    $freeze = @(Invoke-Native $Uv @('pip', 'freeze', '--python', $Python))
    $pins = @($freeze | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]*==\S+$' -and $_ -notmatch '^(hermes-mordred|mordred-hermes)==' })
    [IO.File]::WriteAllLines($constraints, [string[]]$pins, [Text.Encoding]::UTF8)
    $installArgs = @('pip', 'install', '--python', $Python, '--no-python-downloads', '--no-deps', '--reinstall-package', 'hermes-mordred', $package)
    # Preflight resolution before removing the legacy distribution.
    Invoke-Native $Uv ($installArgs + @('--dry-run'))
    $legacyCode = @'
import importlib.metadata as m, json
try: version = m.version('mordred-hermes')
except m.PackageNotFoundError: version = None
print(json.dumps(version))
'@
    $legacy = Read-PythonJson $Python $legacyCode
    if ($legacy) { Invoke-Native $Uv @('pip', 'uninstall', '--python', $Python, 'mordred-hermes') }
    try { Invoke-Native $Uv $installArgs }
    catch {
        if ($legacy) {
            Write-Warning 'Canonical install failed; attempting to restore the legacy package.'
            Invoke-Native $Uv @('pip', 'install', '--python', $Python, '--no-python-downloads', "mordred-hermes==$legacy")
        }
        throw
    }
    $requirementsCode = @'
import importlib.metadata as m, json
from packaging.requirements import Requirement
result = []
for line in m.requires('hermes-mordred') or []:
 r = Requirement(line)
 if r.name.lower().replace('_', '-') in ('hermes-agent', 'hermes-mordred'): continue
 if r.marker is None or any(r.marker.evaluate({'extra': e}) for e in ('', 'keyvault', 'extension')):
  r.marker = None
  result.append(str(r))
print(json.dumps(result))
'@
    $requirements = @(Read-PythonJson $Python $requirementsCode)
    if ($requirements.Count) {
        Invoke-Native $Uv (@('pip', 'install', '--python', $Python, '--no-python-downloads', '--constraint', $constraints) + $requirements)
    }
    $verify = @'
import importlib.metadata as m, json, os, sys
import mordred_hermes
from mordred_hermes.wizard import _windows_install, keyvault_native_cli
from hermes_cli.plugins import PluginManager
entries = [e for e in m.distribution('hermes-mordred').entry_points if e.group == 'hermes_agent.plugins']
assert len(entries) == 1 and entries[0].name == 'mordred' and callable(entries[0].load().register), 'single Mordred registration is missing'
manager = PluginManager()
manifest = next((p for p in manager._scan_entry_points() if p.name == 'mordred'), None)
assert manifest is not None and callable(manager._load_entrypoint_module(manifest).register), 'installed Hermes cannot discover/load Mordred'
assert os.path.isfile(os.path.join(sys.prefix, 'Scripts', 'hermes-mordred.exe')) or os.path.isfile(os.path.join(sys.prefix, 'hermes-mordred.exe')), 'console executable missing'
assert callable(keyvault_native_cli.enable_winkey), 'selected distribution does not contain native Windows wizard code'
print(json.dumps(dict(python=sys.executable, module=mordred_hermes.__file__, version=m.version('hermes-mordred'))))
'@
    $verified = Read-PythonJson $Python $verify
    Invoke-Native $Python @('-m', 'mordred_hermes.wizard._windows_install', 'launcher', $Python, (Join-Path $homePath 'bin'))
    if (-not $InstallOnly) {
        Invoke-Native $Python @('-c', $cliCode, 'plugins', 'migrate', '--only-legacy')
        if ($Action -ne 'install') {
            Invoke-Native $Python (@('-c', $cliCode, $Action) + $CommandArgs)
        }
    }
    Write-Output "Package verified: $($verified.version); Python: $($verified.python); module: $($verified.module)"
    if ($InstallOnly) { Write-Output 'Installation-only validation completed. Configure/setup and native TPM readiness remain separate gates.' }
    elseif ($Action -eq 'install') { Write-Output 'Mordred installed. Run hermes-mordred configure or setup to configure this profile.' }
    else { Write-Output "$Action completed." }
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
} finally {
    if ($constraints -and [IO.File]::Exists($constraints)) { [IO.File]::Delete($constraints) }
}
