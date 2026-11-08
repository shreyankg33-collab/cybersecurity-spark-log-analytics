# ==============================================================================
# Dockerfile: Cybersecurity Log Analytics with Apache Spark and Scala
# ==============================================================================
FROM eclipse-temurin:8-jdk-focal AS builder

WORKDIR /app

# Install sbt
RUN apt-get update && \
    apt-get install -y curl gnupg && \
    echo "deb https://repo.scala-sbt.org/scalasbt/debian all main" | tee /etc/apt/sources.list.d/sbt.list && \
    curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | apt-key add && \
    apt-get update && \
    apt-get install -y sbt

# Copy project files
COPY build.sbt /app/
COPY project /app/project
COPY src /app/src
COPY data /app/data

# Compile and package application
RUN sbt compile

# Runtime stage
ENTRYPOINT ["sbt"]
CMD ["run data/sample_access.log output/security_report"]
