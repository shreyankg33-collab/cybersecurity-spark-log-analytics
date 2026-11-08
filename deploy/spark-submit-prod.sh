#!/usr/bin/env bash
# ==============================================================================
# Production Cluster Deployment Script using spark-submit
# Deployable to: Standalone Spark Cluster, YARN (Hadoop), or Kubernetes
# ==============================================================================
set -e

SPARK_MASTER=${SPARK_MASTER:-"spark://spark-master:7077"}
JAR_PATH=${1:-"target/scala-2.12/cybersecurity-log-analytics.jar"}
INPUT_LOG=${2:-"hdfs:///var/log/nginx/access.log"}
OUTPUT_DIR=${3:-"hdfs:///security/reports/$(date +%Y%m%d_%H%M%S)"}

echo "=============================================================================="
echo " Submitting Cybersecurity Log Analyzer to Spark Cluster: $SPARK_MASTER"
echo "=============================================================================="

# Build Fat JAR if not already built
if [ ! -f "$JAR_PATH" ]; then
    echo "[*] Packaging Fat JAR via sbt assembly..."
    sbt assembly
fi

spark-submit \
  --class com.cybersec.analytics.LogAnalyzerApp \
  --master "$SPARK_MASTER" \
  --deploy-mode cluster \
  --driver-memory 4G \
  --driver-cores 2 \
  --executor-memory 8G \
  --executor-cores 4 \
  --num-executors 6 \
  --conf spark.default.parallelism=48 \
  --conf spark.sql.shuffle.partitions=48 \
  "$JAR_PATH" \
  "$INPUT_LOG" \
  "$OUTPUT_DIR"

echo "[+] Job successfully submitted to Spark cluster."
