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
