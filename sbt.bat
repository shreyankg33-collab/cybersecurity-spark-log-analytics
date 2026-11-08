@echo off
setlocal
set SCRIPT_DIR=%~dp0
set SBT_JAR=%SCRIPT_DIR%project\sbt-launch-1.9.8.jar

if not exist "%SBT_JAR%" (
    echo [INFO] sbt-launch.jar not found. Auto-downloading portable sbt launcher...
    
    REM Method 1: Try PowerShell via full path
    if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
        "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.9.8/sbt-launch-1.9.8.jar', '%SBT_JAR%')"
    )

    REM Method 2: Fallback to certutil if not downloaded yet
    if not exist "%SBT_JAR%" (
        echo [INFO] Trying certutil download fallback...
        certutil -urlcache -split -f "https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.9.8/sbt-launch-1.9.8.jar" "%SBT_JAR%" >nul 2>&1
    )

    REM Method 3: Fallback to curl if present
    if not exist "%SBT_JAR%" (
        where curl >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            curl -fL "https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.9.8/sbt-launch-1.9.8.jar" -o "%SBT_JAR%"
        )
    )

    if not exist "%SBT_JAR%" (
        echo [ERROR] Failed to download sbt-launch.jar automatically.
        echo Please ensure you are connected to the internet.
        exit /b 1
    )
    echo [INFO] Download completed successfully.
)

java -Xms512M -Xmx2048M -jar "%SBT_JAR%" %*
