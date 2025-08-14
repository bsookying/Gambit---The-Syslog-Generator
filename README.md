# Gambit

**Custom Syslog Generator**
Gambit is a Syslog Generator is a Python-based web application designed to simulate and send realistic syslog events to a SIEM platform. It is a powerful tool for security professionals to test detection rules, validate log ingestion, and train analysts in a controlled environment.

**Features**
Flexible Log Generation: Sends logs from five different sources (http, ftp, router, switch, firewall) in popular formats including RFC3164, RFC5424, CEF, and LEEF.

**Randomization Mode**: Generates a continuous, random stream of logs for baseline traffic analysis and load testing.

**Story Mode**: Simulates specific security incidents with a pre-defined sequence of events, allowing you to tell a security narrative. Current stories include:

  - Rogue Insider
  
  - Web Server Breach
  
  - Brute-Force & Data Theft

Noise Injection: Adds random background logs to Story Mode, making it more challenging and realistic to simulate real-world traffic.

Real-time Log Display: A live console in the web interface shows the logs as they are being sent.

** I have no intentions to do any more development on this tool - share your modifications! **
