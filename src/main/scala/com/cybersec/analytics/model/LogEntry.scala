package com.cybersec.analytics.model

import java.sql.Timestamp

/**
 * Case class representing a structured web server access log entry.
 * Follows the W3C / Apache / Nginx Combined Log Format standard:
 * %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
 */
case class LogEntry(
    clientIp: String,
    identd: String,
    authUser: String,
    rawTimestamp: String,
    timestamp: Timestamp,
    method: String,
    endpoint: String,
    protocol: String,
    statusCode: Int,
    responseBytes: Long,
    referrer: String,
    userAgent: String
)
