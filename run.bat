@echo off
setlocal
echo ==============================================================================
echo   Starting Cybersecurity Log Analytics with Apache Spark and Scala
echo ==============================================================================

if "%~1"=="" (
    set INPUT_LOG=data\sample_access.log
) else (
    set INPUT_LOG=%~1
)

if "%~2"=="" (
    set OUTPUT_DIR=output\security_report
) else (
    set OUTPUT_DIR=%~2
)

echo Input Log File  : %INPUT_LOG%
echo Output Directory: %OUTPUT_DIR%
echo.

where sbt >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] Using system installed sbt...
    sbt "run %INPUT_LOG% %OUTPUT_DIR%"
) else (
    echo [*] System 'sbt' not found. Using portable sbt launcher...
    call "%~dp0sbt.bat" "run %INPUT_LOG% %OUTPUT_DIR%"
)

pause
