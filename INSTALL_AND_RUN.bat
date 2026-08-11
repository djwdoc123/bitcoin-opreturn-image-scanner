@echo off
title Bitcoin OP_RETURN FINAL Raw-Block Scanner
cd /d "%~dp0"
echo ============================================================
echo Bitcoin OP_RETURN FINAL raw-block scanner
echo Strict complete images inside ONE OP_RETURN output only
echo ============================================================
echo.
echo Installing/updating Pillow...
python -m pip install --upgrade Pillow
if errorlevel 1 (
    echo.
    echo ERROR: Pillow installation failed.
    pause
    exit /b 1
)
echo.
echo Starting scanner...
echo To stop later: click this black window and press Ctrl+C.
echo.
python opreturn_image_scanner.py --follow
echo.
pause
