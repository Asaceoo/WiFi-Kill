@echo off
REM WiFiKill 一键从源码运行（不打包、不签名；适合核对源码或没有 exe 的环境）
REM 用法：tools\run_from_source.bat            正常启动
REM       tools\run_from_source.bat --dry-run  教学/演练模式（绝不发真实报文）
setlocal
cd /d "%~dp0.."

if not exist .buildenv\Scripts\python.exe (
  echo [*] 首次运行：创建 .buildenv 虚拟环境并安装 scapy ...
  python -m venv .buildenv || goto :fail
  .buildenv\Scripts\python.exe -m pip install --upgrade pip >nul || goto :fail
  .buildenv\Scripts\python.exe -m pip install scapy || goto :fail
)

.buildenv\Scripts\python.exe -c "import scapy, tkinter" 2>nul || (
  echo [!] 依赖不完整（需要 scapy 与自带 tkinter 的 Python 3.10+），尝试补装 scapy ...
  .buildenv\Scripts\python.exe -m pip install scapy || goto :fail
)

echo [*] 启动 WiFiKill（源码模式）。注意：发包仍需先安装 Npcap。
.buildenv\Scripts\python.exe gui.py %*
goto :eof

:fail
echo [-] 启动失败：请确认已安装 Python 3.10+（含 tkinter）并联网可装 scapy。
pause
exit /b 1
