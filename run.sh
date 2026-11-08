#!/usr/bin/env bash
set -e

echo "=============================================================================="
echo "  Starting Cybersecurity Log Analytics with Apache Spark and Scala"
echo "=============================================================================="

INPUT_LOG=${1:-data/sample_access.log}
OUTPUT_DIR=${2:-output/security_report}

echo "Input Log File  : $INPUT_LOG"
echo "Output Directory: $OUTPUT_DIR"
echo ""

sbt "run $INPUT_LOG $OUTPUT_DIR"
