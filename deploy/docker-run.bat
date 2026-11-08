@echo off
echo ==============================================================================
echo   Deploying Cybersecurity Log Analytics with Docker
echo ==============================================================================

where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not found on your system PATH.
    echo Please install Docker Desktop: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

echo [*] Building and starting Docker container...
docker compose up --build
pause
