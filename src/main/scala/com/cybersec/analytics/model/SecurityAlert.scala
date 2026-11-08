package com.cybersec.analytics.model

import java.sql.Timestamp

/**
 * Case class representing a detected security incident alert.
 */
case class SecurityAlert(
    alertId: String,
    timestamp: Timestamp,
    clientIp: String,
    threatCategory: String,
    severity: String,
    endpoint: String,
    matchedPattern: String,
    description: String,
    riskWeight: Int
)

object SeverityLevels {
  val CRITICAL = "CRITICAL"
  val HIGH     = "HIGH"
  val MEDIUM   = "MEDIUM"
  val LOW      = "LOW"
}

object ThreatCategories {
  val SQL_INJECTION    = "SQL_INJECTION"
  val XSS              = "XSS_ATTACK"
  val PATH_TRAVERSAL   = "PATH_TRAVERSAL"
  val SENSITIVE_FILE   = "SENSITIVE_FILE_EXPOSURE"
  val BRUTE_FORCE      = "BRUTE_FORCE_AUTH"
  val DOS_FLOODING     = "DOS_RATE_LIMIT"
  val RECON_SCANNER    = "RECON_TOOL_SCAN"
  val RECON_PROBING    = "RECON_404_PROBE"
}
