python3 sqli_scanner.py -u http://example.com -p payloads.txt --timeout 30

**Comprehensive Logging System:**

Creates a unique log directory for each scan with timestamp.
Logs all activities including crawling, parameter detection, and testing.
Separate log files for crawled URLs, parameters, forms, and vulnerabilities.
Detailed logs of each payload test with URL, parameter, and response data.

**Sequential Testing of Payloads:**

Switched from parallel to sequential testing to ensure every payload is tested.
Each payload is now methodically tested against each parameter.
Detailed tracking of which payload was tested against which parameter.

**Improved Error Handling:**

Better error catching and logging for connection issues.
Handles timeouts more gracefully.
Logs all errors to help diagnose issues.

**Enhanced Reporting:**

JSON formatted output files for easy analysis.
Saves vulnerability details immediately when found.
Creates a comprehensive final report.
