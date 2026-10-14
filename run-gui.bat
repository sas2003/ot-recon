@echo off
title OT-Recon GUI Launcher
echo Starting OT-Recon GUI...
python -m ot_recon.gui %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Failed to launch OT-Recon GUI.
    echo Ensure required dependencies are installed:
    echo     pip install -e ".[gui]"
    pause
)
