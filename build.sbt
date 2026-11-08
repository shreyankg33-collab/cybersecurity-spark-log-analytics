name := "cybersecurity-log-analytics-spark-scala"

version := "1.0.0"

scalaVersion := "2.12.18"

val sparkVersion = "3.5.0"

// Dependencies
libraryDependencies ++= Seq(
  "org.apache.spark" %% "spark-core" % sparkVersion,
  "org.apache.spark" %% "spark-sql"  % sparkVersion,
  "org.scalatest"    %% "scalatest"  % "3.2.17" % Test
)

// JVM options configured for Java 8 compatibility and localhost binding
javaOptions ++= Seq(
  "-Xms512M",
  "-Xmx2G",
  "-Dspark.driver.host=localhost",
  "-Dspark.driver.bindAddress=127.0.0.1",
  "-Dfile.encoding=UTF-8"
)

fork in run := true
fork in Test := true

// SBT Assembly configuration for Fat JAR generation
assembly / assemblyJarName := "cybersecurity-log-analytics.jar"
assembly / mainClass := Some("com.cybersec.analytics.LogAnalyzerApp")

assembly / assemblyMergeStrategy := {
  case PathList("META-INF", xs @ _*) =>
    xs match {
      case "MANIFEST.MF" :: Nil => MergeStrategy.discard
      case "services" :: _      => MergeStrategy.concat
      case _                    => MergeStrategy.discard
    }
  case "reference.conf" => MergeStrategy.concat
  case _                => MergeStrategy.first
}
