# Cybersecurity Data Analytics: A Scala & Spark Approach to Log Analysis

[![Scala Version](https://img.shields.io/badge/Scala-2.12.18-red.svg)](https://www.scala-lang.org/)
[![Apache Spark](https://img.shields.io/badge/Apache_Spark-3.5.0-orange.svg)](https://spark.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An end-to-end, high-throughput log analytics and intrusion detection system built with **Apache Spark (Core & SQL)** and **Scala**. This project analyzes web server access logs (Apache/Nginx Combined Log Format) at scale to identify, classify, score, and report cyber security incidents.

---

## 📌 Project Purpose & Problem Statement

Modern web infrastructure produces millions of access log events every minute. Sifting through high-volume, unstructured text logs using traditional scripts or manual reviews is insufficient for detecting sophisticated, distributed cyber attacks.

This project addresses this challenge by utilizing **Apache Spark's distributed computing engine** and **Scala's strong typing and functional programming** to build a high-performance detection pipeline that uncovers:
- **Application-layer code injection attacks** (SQLi, XSS).
- **Filesystem and sensitive secret reconnaissance** (Path Traversal, `.env`, `.git` exposures).
- **Automated scanning bots and fuzzers** (`Nikto`, `sqlmap`, `Gobuster`, `Hydra`).
- **Temporal behavioral anomalies** (Credential Brute-Force, volumetric Denial of Service floods).

---

## 🛡️ Threat Detection Matrix & Rules

| Threat Category | Severity | Detection Technique | Example Signature / Behavioral Pattern |
| :--- | :---: | :--- | :--- |
| **SQL Injection (SQLi)** | `CRITICAL` | URL decoded Regex pattern matching | `' OR '1'='1`, `UNION SELECT ... FROM`, `SLEEP()`, `--` |
| **Path Traversal / LFI** | `CRITICAL` | Directory climb and system path inspection | `../../../../etc/passwd`, `%2e%2e%2f`, `win.ini`, `boot.ini` |
| **Cross-Site Scripting (XSS)** | `HIGH` | Script tag & event handler inspection | `<script>`, `%3Cscript%3E`, `javascript:`, `onerror=alert()` |
| **Sensitive File Exposure** | `HIGH` | Secret/admin path targeting | `/.env`, `/.git/config`, `/wp-config.php`, `backup.sql` |
| **Credential Brute Force** | `HIGH` | Sliding Window analysis on auth endpoints | $\ge 3$ consecutive HTTP 401/403 responses within 60 seconds |
| **Denial of Service (DoS)** | `MEDIUM` | Sliding Window request rate velocity | $\ge 15$ requests from a single IP within a 60-second window |
| **Reconnaissance Probing** | `MEDIUM` | Distinct 404 endpoint aggregation | $\ge 4$ unique 404 (Not Found) endpoints probed by a single IP |
| **Vulnerability Scanners** | `MEDIUM` | User-Agent signature fingerprinting | `Nikto`, `sqlmap`, `nmap`, `gobuster`, `Hydra`, `dirbuster` |

---

## 🏗️ Architecture & Data Pipeline

```
                                  +------------------------------+
                                  |   Web Server Access Logs     |
                                  | (Apache / Nginx Combined)    |
                                  +--------------+---------------+
                                                 |
                                                 v
                                  +------------------------------+
                                  |    Spark Ingestion & Parser  |
                                  | (LogParser: Regex & Decoders)|
                                  +--------------+---------------+
                                                 |
                                                 v
                                    Dataset[LogEntry] (Cached)
                                                 |
            +------------------------------------+------------------------------------+
            |                                    |                                    |
            v                                    v                                    v
  +--------------------+               +--------------------+               +--------------------+
  | Signature Detector |               |  Anomaly Detector  |               |   Recon Detector   |
  |  - SQLi            |               |  - Brute Force     |               |  - Scanner UAs     |
  |  - XSS             |               |    (Windowed 401s) |               |  - 404 Fuzzing     |
  |  - Path Traversal  |               |  - DoS Rate Floods |               |                    |
  |  - Sensitive Files |               |    (Sliding Counts)|               |                    |
  +---------+----------+               +---------+----------+               +---------+----------+
            |                                    |                                    |
            +------------------------------------+------------------------------------+
                                                 |
                                                 v
                                   Dataset[SecurityAlert]
                                                 |
                                                 v
                                  +------------------------------+
                                  |  Security Threat Aggregator  |
                                  |  & Multi-Factor Risk Scorer  |
                                  +--------------+---------------+
                                                 |
                         +-----------------------+-----------------------+
                         |                                               |
                         v                                               v
              [ Formatted Console UI ]                      [ SIEM Artifacts Export ]
           - Severity Breakdown Tables                     - JSON Alerts (`output/`)
           - Top Malicious IPs Matrix                      - CSV Threat Matrix (`output/`)
```

---

## 📂 Project Structure

```
cybersecurity-log-analytics-spark-scala/
├── build.sbt                                 # Spark 3.5.0 & Scala dependencies
├── project/
│   └── build.properties                      # SBT version (1.9.8)
├── run.bat                                   # One-click Windows runner
├── run.sh                                    # Unix/Linux/macOS runner
├── data/
│   └── sample_access.log                     # Realistic access logs with embedded attacks
├── scripts/
│   └── generate_synthetic_logs.py            # Scalable synthetic log generator (1k-1M+ lines)
├── src/
│   ├── main/
│   │   ├── resources/
│   │   │   └── log4j2.properties             # Spark log filter (suppresses non-security noise)
│   │   └── scala/com/cybersec/analytics/
│   │       ├── LogAnalyzerApp.scala          # Main entry point & Spark pipeline coordinator
│   │       ├── config/
│   │       │   └── SecurityConfig.scala      # Detection rules, regex patterns & thresholds
│   │       ├── model/
│   │       │   ├── LogEntry.scala            # Case class for parsed log rows
│   │       │   └── SecurityAlert.scala       # Case class & constants for alerts
│   │       ├── parser/
│   │       │   └── LogParser.scala           # Resilient Combined Log Format parser
│   │       ├── detector/
│   │       │   ├── SignatureDetector.scala   # SQLi, XSS, Path Traversal detection
│   │       │   ├── AnomalyDetector.scala     # Windowed Brute-Force & DoS detection
│   │       │   └── ReconDetector.scala       # 404 scanning & scanner user-agents
│   │       └── reporter/
│   │           └── SecurityReporter.scala    # IP risk scoring, reporting & SIEM export
│   └── test/
│       └── scala/com/cybersec/analytics/
│           └── LogParserSpec.scala           # ScalaTest unit test suite
└── README.md                                 # Complete documentation
```

---

## ⚙️ Prerequisites & Installation

1. **Java Development Kit (JDK)**: JDK 8, 11, or 17 installed and on your system `PATH`.
   ```bash
   java -version
   ```
2. **Scala & sbt**: [sbt (Scala Build Tool)](https://www.scala-sbt.org/download.html) 1.9.0+.
   ```bash
   sbt -version
   ```

*(Note: Apache Spark does not need to be pre-installed on your system; `sbt` automatically downloads the Apache Spark 3.5.0 libraries during compilation.)*

---

## 🚀 How to Run the Project

### 1. Quick Execution (Default Sample Data)

**On Windows:**
```cmd
run.bat
```
or via sbt directly:
```cmd
sbt "run data/sample_access.log output/security_report"
```

**On Linux / macOS:**
```bash
chmod +x run.sh
./run.sh
```

### 2. Running Automated Unit Tests
To verify the log parser and attack signatures:
```bash
sbt test
```

### 3. Generating Custom Scale Datasets (Stress Testing)
To generate a larger dataset (e.g. 5,000 log lines with randomized benign and attack traffic):
```bash
python scripts/generate_synthetic_logs.py 5000 data/large_access.log
sbt "run data/large_access.log output/large_security_report"
```

### 4. Running on a Distributed Spark Cluster (`spark-submit`)
To deploy the compiled application to a production Hadoop/YARN or Kubernetes Spark cluster:
```bash
# Package into JAR
sbt package

# Submit to cluster
spark-submit \
  --class com.cybersec.analytics.LogAnalyzerApp \
  --master yarn \
  --deploy-mode cluster \
  --driver-memory 4G \
  --executor-memory 8G \
  target/scala-2.12/cybersecurity-log-analytics-spark-scala_2.12-1.0.0.jar \
  hdfs:///logs/web_server_access.log \
  hdfs:///security/reports
```

---

## 📊 Sample Security Intelligence Output

When running against `data/sample_access.log`, the Spark pipeline outputs a comprehensive incident dashboard:

```text
==========================================================================================
  CYBERSECURITY DATA ANALYTICS: SCALA & SPARK ACCESS LOG DETECTOR        
==========================================================================================
  Target Log File   : data/sample_access.log
  Output Directory  : output/security_report
==========================================================================================

[*] [Phase 1/4] Ingesting and parsing web server access logs...
    -> Successfully parsed 51 log entries into structured Dataset[LogEntry].

[*] [Phase 2/4] Running Security Detection Engines...
    [+] Executing Signature Detection Engine (SQLi, XSS, LFI)...
    [+] Executing Behavioral Anomaly Engine (Brute-Force & DoS)...
    [+] Executing Reconnaissance & Scanner Detection Engine...

[*] [Phase 3/4] Aggregating multi-vector security alerts...

[*] [Phase 4/4] Compiling Threat Intelligence & Risk Matrix...

==========================================================================================
                      CYBERSECURITY LOG ANALYTICS REPORT                     
==========================================================================================
 Total Logs Processed   : 51
 Total Incidents Flagged: 21
==========================================================================================

[+] INCIDENTS BY SEVERITY LEVEL:
+--------+-----+
|severity|Count|
+--------+-----+
|CRITICAL|10   |
|HIGH    |7    |
|MEDIUM  |4    |
+--------+-----+

[+] INCIDENTS BY THREAT CATEGORY:
+------------------------+--------+---------+
|threatCategory          |severity|Incidents|
+------------------------+--------+---------+
|SQL_INJECTION           |CRITICAL|4        |
|PATH_TRAVERSAL          |CRITICAL|6        |
|XSS_ATTACK              |HIGH    |4        |
|SENSITIVE_FILE_EXPOSURE |HIGH    |2        |
|BRUTE_FORCE_AUTH        |HIGH    |1        |
|RECON_TOOL_SCAN         |MEDIUM  |2        |
|RECON_404_PROBE         |MEDIUM  |1        |
|DOS_RATE_LIMIT          |MEDIUM  |1        |
+------------------------+--------+---------+

[+] TOP MALICIOUS IP ADDRESSES (BY THREAT SCORE):
+---------------+--------------+-----------+------------------------------------------------------+---------------+
|clientIp       |totalRiskScore|totalAlerts|attackTypes                                           |threatRating   |
+---------------+--------------+-----------+------------------------------------------------------+---------------+
|203.0.113.45   |400           |4          |[SQL_INJECTION]                                       |CRITICAL THREAT|
|198.51.100.89  |300           |4          |[PATH_TRAVERSAL, SENSITIVE_FILE_EXPOSURE]             |CRITICAL THREAT|
|198.51.100.22  |200           |4          |[XSS_ATTACK]                                          |CRITICAL THREAT|
|192.241.220.11 |75            |2          |[RECON_TOOL_SCAN, RECON_404_PROBE]                    |HIGH RISK      |
|185.220.101.5  |50            |1          |[BRUTE_FORCE_AUTH]                                    |HIGH RISK      |
|45.33.32.156   |25            |1          |[DOS_RATE_LIMIT]                                      |SUSPICIOUS     |
+---------------+--------------+-----------+------------------------------------------------------+---------------+

[+] Exporting detailed alerts to: output/security_report/security_alerts_json ...
[+] Exporting IP threat matrix to: output/security_report/malicious_ips_csv ...
```

---

## 🔮 Production Extensions

1. **Spark Structured Streaming + Apache Kafka**:
   Replace batch file ingestion (`spark.read.textFile`) with streaming (`spark.readStream.format("kafka")`) to achieve sub-second real-time alert generation and automated firewall IP blocking.
2. **Machine Learning Anomaly Detection (Spark MLlib)**:
   Integrate K-Means clustering or Isolation Forests on numerical features (request payload length, request frequency, entropy of request URI) to identify zero-day attacks without predefined signatures.
3. **SIEM & SOAR Integration**:
   Forward the exported JSON alerts into **Splunk**, **Elasticsearch / Kibana**, or **AWS OpenSearch** dashboards.

---

## 📜 License
MIT License. Created for Cybersecurity Data Analytics education and research.
