package com.cybersec.analytics.config

import com.cybersec.analytics.model.SeverityLevels

object SecurityConfig {

  // Severity Weightings for IP Risk Scoring
  val SeverityWeights: Map[String, Int] = Map(
    SeverityLevels.CRITICAL -> 100,
    SeverityLevels.HIGH     -> 50,
    SeverityLevels.MEDIUM   -> 25,
    SeverityLevels.LOW      -> 10
  )

  // Regular expressions for Signature-based detections (case-insensitive in Spark)
  // 1. SQL Injection: UNION, SELECT, OR 1=1, SLEEP(), DROP, COMMENT dashes, INFORMATION_SCHEMA
  val SqlInjectionRegex: String =
    "(?i)(\\bunion\\b.+?\\bselect\\b|'\\s*(or|and)\\s*['\"\\d]+=['\"\\d]+|\\bsleep\\(\\d+\\)|--|;\\s*drop\\b|\\binformation_schema\\b|\\bbenchmark\\()"

  // 2. Cross-Site Scripting (XSS): <script>, javascript:, onerror=, onload=, %3Cscript%3E
  val XssRegex: String =
    "(?i)(<script.*?>|%3cscript.*?%3e|javascript\\s*:|onerror\\s*=|onload\\s*=|eval\\(|alert\\()"

  // 3. Path Traversal & Local File Inclusion: ../, ..%2f, ..%5c, \..\
  val PathTraversalRegex: String =
    "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|%2e%2e%5c|/etc/passwd|/etc/shadow|c:\\\\windows|c:/windows|win.ini|boot.ini)"

  // 4. Sensitive Files & Admin Endpoints Exposure: .env, .git, wp-config, backup.sql, .htpasswd
  val SensitiveFilesRegex: String =
    "(?i)(\\.env|\\.git/|\\.htpasswd|wp-config\\.php|config\\.inc\\.php|server-status|\\.aws/|backup\\.sql|dump\\.sql)"

  // 5. Known Automated Vulnerability Scanners & Reconnaissance Tools User-Agents
  val ScannerUserAgentsRegex: String =
    "(?i)(nikto|sqlmap|nmap|gobuster|dirbuster|wpscan|masscan|hydra|zgrab|nessus|acunetix|burpsuite|python-requests/|curl/)"

  // Thresholds for Behavioral Anomaly Detection
  // Brute Force: Number of 401/403 status responses on auth endpoints within window
  val BruteForceAuthWindowSeconds: Long = 60
  val BruteForceFailureThreshold: Int   = 3
  val AuthEndpointsRegex: String        = "(?i)(/login|/auth|/api/v1/auth|/admin/login|/signin|/oauth/token)"

  // Denial of Service (DoS): Number of requests per IP within sliding window
  val DosWindowSeconds: Long = 60
  val DosRequestThreshold: Int = 15

  // Reconnaissance Probing: Number of 404 (Not Found) responses per IP within sliding window
  val ReconWindowSeconds: Long = 120
  val Recon404Threshold: Int = 4
}
