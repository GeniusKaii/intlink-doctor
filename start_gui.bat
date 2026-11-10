@echo off
REM 双击启动 intlink-doctor 图形界面
REM 需要 Python 3.8+；不需要装任何第三方包（tkinter 随 Python 自带）
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 找不到 python。请先安装 Python 3.8+ 并勾选 "Add to PATH"。
  pause
  exit /b 1
)

python -c "import tkinter" >nul 2>nul
if errorlevel 1 (
  echo [错误] 当前 Python 没有 tkinter。重装 Python 时勾选 "tcl/tk and IDLE"。
  pause
  exit /b 1
)

python -m intlink_doctor %*
if errorlevel 1 pause
