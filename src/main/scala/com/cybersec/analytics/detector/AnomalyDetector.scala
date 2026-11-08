package com.cybersec.analytics.detector

import com.cybersec.analytics.config.SecurityConfig
import com.cybersec.analytics.model.{LogEntry, SecurityAlert, SeverityLevels, ThreatCategories}
import org.apache.spark.sql.expressions.Window
import org.apache.spark.sql.functions._
import org.apache.spark.sql.{Dataset, SparkSession}

/**
 * Behavioral Anomaly Detector.
 * Leverages Spark SQL Windowing functions to calculate sliding-window metrics:
 * 1. Authentication Brute Force: High volume of 401/403 failures on login endpoints.
 * 2. Denial of Service (DoS): High request velocity per IP within a short timeframe.
 */
object AnomalyDetector extends Serializable {

  def detectAnomalies(spark: SparkSession, logs: Dataset[LogEntry]): Dataset[SecurityAlert] = {
    import spark.implicits._

    val bruteForceAlerts = detectBruteForce(spark, logs)
    val dosAlerts        = detectDosFlooding(spark, logs)

    bruteForceAlerts.union(dosAlerts)
  }

  /**
   * Detects credential brute force attacks using sliding time window on auth endpoints.
   */
  def detectBruteForce(spark: SparkSession, logs: Dataset[LogEntry]): Dataset[SecurityAlert] = {
    import spark.implicits._

    // Filter failed attempts on authentication endpoints
    val authFailures = logs
      .filter(
        $"endpoint".rlike(SecurityConfig.AuthEndpointsRegex) &&
        ($"statusCode" === 401 || $"statusCode" === 403)
      )
      .withColumn("epochSeconds", $"timestamp".cast("long"))

    // Sliding window of BruteForceAuthWindowSeconds per client IP
    val windowSpec = Window
      .partitionBy($"clientIp")
      .orderBy($"epochSeconds")
      .rangeBetween(-SecurityConfig.BruteForceAuthWindowSeconds, 0)

    val flaggedFailures = authFailures
      .withColumn("failureCountInWindow", count("*").over(windowSpec))
      .filter($"failureCountInWindow" >= SecurityConfig.BruteForceFailureThreshold)
      // Pick the highest count per IP to emit clean consolidated alerts
      .groupBy($"clientIp")
      .agg(
        max($"timestamp").as("lastIncidentTime"),
        max($"failureCountInWindow").as("totalFailures"),
        first($"endpoint").as("targetEndpoint")
      )

    flaggedFailures.map { row =>
      val ip            = row.getAs[String]("clientIp")
      val ts            = row.getAs[java.sql.Timestamp]("lastIncidentTime")
      val failures      = row.getAs[Long]("totalFailures")
      val endpoint      = row.getAs[String]("targetEndpoint")
      SecurityAlert(
        alertId = s"BRUTE-${java.util.UUID.randomUUID().toString.take(8)}",
        timestamp = ts,
        clientIp = ip,
        threatCategory = ThreatCategories.BRUTE_FORCE,
        severity = SeverityLevels.HIGH,
        endpoint = endpoint,
        matchedPattern = s"$failures failed auth attempts within ${SecurityConfig.BruteForceAuthWindowSeconds}s",
        description = s"Credential brute-force attack detected from $ip targeting $endpoint ($failures consecutive failures)",
        riskWeight = SecurityConfig.SeverityWeights(SeverityLevels.HIGH)
      )
    }
  }

  /**
   * Detects volumetric Denial of Service / request flooding per client IP.
   */
  def detectDosFlooding(spark: SparkSession, logs: Dataset[LogEntry]): Dataset[SecurityAlert] = {
    import spark.implicits._

    val logsWithEpoch = logs.withColumn("epochSeconds", $"timestamp".cast("long"))

    // Sliding window of DosWindowSeconds per client IP
    val dosWindow = Window
      .partitionBy($"clientIp")
      .orderBy($"epochSeconds")
      .rangeBetween(-SecurityConfig.DosWindowSeconds, 0)

    val flaggedDos = logsWithEpoch
      .withColumn("requestRateInWindow", count("*").over(dosWindow))
      .filter($"requestRateInWindow" >= SecurityConfig.DosRequestThreshold)
      .groupBy($"clientIp")
      .agg(
        max($"timestamp").as("peakIncidentTime"),
        max($"requestRateInWindow").as("peakRequests"),
        first($"endpoint").as("sampleEndpoint")
      )

    flaggedDos.map { row =>
      val ip       = row.getAs[String]("clientIp")
      val ts       = row.getAs[java.sql.Timestamp]("peakIncidentTime")
      val reqCount = row.getAs[Long]("peakRequests")
      val endpoint = row.getAs[String]("sampleEndpoint")
      SecurityAlert(
        alertId = s"DOS-${java.util.UUID.randomUUID().toString.take(8)}",
        timestamp = ts,
        clientIp = ip,
        threatCategory = ThreatCategories.DOS_FLOODING,
        severity = SeverityLevels.MEDIUM,
        endpoint = endpoint,
        matchedPattern = s"Rate spike: $reqCount reqs within ${SecurityConfig.DosWindowSeconds}s",
        description = s"Potential DoS / rate flood anomaly: $ip generated $reqCount requests within ${SecurityConfig.DosWindowSeconds}s",
        riskWeight = SecurityConfig.SeverityWeights(SeverityLevels.MEDIUM)
      )
    }
  }
}
