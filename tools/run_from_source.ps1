# WiFiKill 一键从源码运行（PowerShell 版）
# 用法： pwsh -File tools\run_from_source.ps1            正常启动
#        pwsh -File tools\run_from_source.ps1 --dry-run  教学/演练模式（绝不发真实报文）
$ErrorActionPreference = "stop"
Set-Location (Join-Path $PSScriptRoot "..")

$py = ".buildenv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "[*] 首次运行：创建 .buildenv 并安装 scapy ..."
    python -m venv .buildenv
    & $py -m pip install --upgrade pip | Out-Null
    & $py -m pip install scapy
}

& $py -c "import scapy, tkinter" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] 依赖不完整，补装 scapy ..."
    & $py -m pip install scapy
}

Write-Host "[*] 启动 WiFiKill（源码模式）。发包仍需先安装 Npcap。"
& $py gui.py @args
