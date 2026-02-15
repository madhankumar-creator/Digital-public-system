@echo off
echo Starting DPIRTS Digital Issue Reporting System...
echo.
echo Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in your PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b
)

echo installing dependencies if needed...
pip install -r requirements.txt

echo.
echo Starting the server...
echo Access the application at: http://127.0.0.1:8080
echo Press Ctrl+C to stop the server.
echo.
python app.py
pause
