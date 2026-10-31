@echo off
rem 无控制台窗口启动 ZCode 体验套餐额度悬浮窗
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0quota_widget.py"
) else (
    start "" pyw "%~dp0quota_widget.py"
)
