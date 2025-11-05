OWASP Scan Reporter

This project is a simple Python-based web security scanner that checks a target website for common vulnerabilities listed in the **OWASP Top 10**.  
It’s designed mainly for educational and lab use, so it runs light, safe scans and generates a **Word report** (`.docx`) summarizing everything it finds.


Features

- Checks for common security misconfigurations (missing headers, insecure cookies, etc.)
- Looks for sensitive files like `.git`, `.env`, and backup directories
- Performs **passive** (non-destructive) vulnerability tests for:
  - SQL Injection  
  - XSS  
  - CSRF  
  - IDOR and other logic flaws
- Creates a neat, professional **Word report** using `python-docx`
- All results are saved inside a timestamped folder under `results_owasp/`


Requirements

- Python 3.8+
- Install dependencies:
  ```bash
  pip install -r requirements.txt

How to run:

Basic usage (passive scan):

  '''python3 owasp_scan_report.py https://example.com'''


Active mode (for lab testing only — requires permission):

  python3 owasp_scan_report.py https://example.com --active


When the scan finishes, it will create a folder under results_owasp/ that contains a Word report and log files.


Note: 
Please do not use this script on websites you don’t own or have written permission to test.
Unauthorized scanning can be illegal in many countries.
This tool is made for learning purposes — perfect for students, ethical hackers, and penetration testers who want to understand the basics of web app testing.


