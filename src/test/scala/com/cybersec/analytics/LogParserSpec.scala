package com.cybersec.analytics

import com.cybersec.analytics.config.SecurityConfig
import com.cybersec.analytics.parser.LogParser
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class LogParserSpec extends AnyFlatSpec with Matchers {

  "LogParser" should "parse a standard Apache Combined Log line correctly" in {
    val sampleLine = """192.168.1.105 - john [10/May/2024:14:32:10 +0000] "GET /products?id=42 HTTP/1.1" 200 4520 "https://example.com" "Mozilla/5.0""""
    val result = LogParser.parseLine(sampleLine)

    result shouldBe defined
    val entry = result.get
    entry.clientIp shouldBe "192.168.1.105"
    entry.authUser shouldBe "john"
    entry.method shouldBe "GET"
    entry.endpoint shouldBe "/products?id=42"
    entry.protocol shouldBe "HTTP/1.1"
    entry.statusCode shouldBe 200
    entry.responseBytes shouldBe 4520L
    entry.referrer shouldBe "https://example.com"
    entry.userAgent shouldBe "Mozilla/5.0"
  }

  it should "return None for malformed or corrupted log entries" in {
    val corruptLine = "This is not a valid combined log format line at all."
    val result = LogParser.parseLine(corruptLine)
    result shouldBe None
  }

  it should "correctly decode percent-encoded URLs" in {
    val encoded = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    val decoded = LogParser.safeUrlDecode(encoded)
    decoded shouldBe "/search?q=<script>alert(1)</script>"
  }

  "SecurityConfig Rules" should "detect SQL Injection patterns" in {
    val sqliUrls = Seq(
      "/items?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
      "/login?user=admin'%20or%20'1'='1",
      "/search?id=1;%20SLEEP(5)--"
    )

    for (url <- sqliUrls) {
      val decoded = LogParser.safeUrlDecode(url)
      (url.matches(SecurityConfig.SqlInjectionRegex) || decoded.matches(SecurityConfig.SqlInjectionRegex)) shouldBe true
    }
  }

  it should "detect Cross-Site Scripting patterns" in {
    val xssUrls = Seq(
      "/profile?name=<script>alert('xss')</script>",
      "/index.php?param=javascript:eval(document.cookie)",
      "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    )

    for (url <- xssUrls) {
      val decoded = LogParser.safeUrlDecode(url)
      (url.matches(SecurityConfig.XssRegex) || decoded.matches(SecurityConfig.XssRegex)) shouldBe true
    }
  }

  it should "detect Path Traversal patterns" in {
    val traversalUrls = Seq(
      "/download?file=../../../../etc/passwd",
      "/view?page=%2e%2e%2f%2e%2e%2fwin.ini",
      "/config?file=../boot.ini"
    )

    for (url <- traversalUrls) {
      val decoded = LogParser.safeUrlDecode(url)
      (url.matches(SecurityConfig.PathTraversalRegex) || decoded.matches(SecurityConfig.PathTraversalRegex)) shouldBe true
    }
  }
}
