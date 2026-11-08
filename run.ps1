param (
    [string]$InputLog = "data\sample_access.log",
    [string]$OutputDir = "output\security_report"
)

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  Starting Cybersecurity Log Analytics with Apache Spark and Scala" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Input Log File  : $InputLog"
Write-Host "Output Directory: $OutputDir"
Write-Host ""

# 1. Check for Java
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Java is not detected on your PATH." -ForegroundColor Red
    Write-Host "Please ensure Java JDK (v8, 11, or 17) is installed." -ForegroundColor Yellow
    exit 1
}

# 2. Check for sbt: use global sbt if present, otherwise auto-download portable sbt-launch.jar
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SbtJar = Join-Path $ScriptDir "project\sbt-launch-1.9.8.jar"

if (Get-Command sbt -ErrorAction SilentlyContinue) {
    Write-Host "[+] Using system installed sbt..." -ForegroundColor Cyan
    sbt "run $InputLog $OutputDir"
} else {
    Write-Host "[*] System 'sbt' not found. Using portable self-bootstrapping sbt launcher..." -ForegroundColor Yellow
    if (-not (Test-Path $SbtJar)) {
        Write-Host "[*] Downloading sbt-launch-1.9.8.jar from Maven Central..." -ForegroundColor Yellow
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.9.8/sbt-launch-1.9.8.jar", $SbtJar)
        Write-Host "[+] Download complete." -ForegroundColor Green
    }
    
    Write-Host "[+] Launching Spark Log Analytics application..." -ForegroundColor Green
    java -Xms512M -Xmx2048M -jar $SbtJar "run $InputLog $OutputDir"
}
