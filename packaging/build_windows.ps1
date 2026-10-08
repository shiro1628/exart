# Windows에서 직접 빌드할 때. 사용: powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
# onedir 로 만든다(onefile 은 실행할 때마다 대상 %TEMP% 에 런타임을 푼다).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP ('exart_build_' + [guid]::NewGuid())
$arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
$name = "exart-windows-$arch"
python -m venv "$work\venv"
& "$work\venv\Scripts\pip.exe" -q install pyinstaller==6.11.1
& "$work\venv\Scripts\pyinstaller.exe" --onedir --clean --noconfirm --name $name `
  --distpath "$root\dist" --workpath "$work\build" --specpath $work "$root\exart_run.py"
New-Item -ItemType Directory -Force "$root\dist\$name\tools" | Out-Null
Copy-Item -Recurse -Force "$root\tools\windows" "$root\dist\$name\tools\"
& "$root\dist\$name\$name.exe" --version
Compress-Archive -Force "$root\dist\$name" "$root\dist\$name.zip"
Get-FileHash "$root\dist\$name.zip", "$root\dist\$name\$name.exe" -Algorithm SHA256
Remove-Item -Recurse -Force $work
