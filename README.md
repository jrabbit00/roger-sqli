# Roger SQLi 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**SQL injection vulnerability scanner for bug bounty hunting.**

Tests 30+ SQLi payloads including error-based, boolean-based, time-based, and UNION-based detection methods.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why SQLi?

SQL injection is a critical vulnerability:
- Data breach (users, passwords, payments)
- Database takeover
- Remote code execution in some cases
- High bug bounty payouts

## Features

- Tests 30+ SQLi payloads
- Error-based detection
- Boolean-based detection
- Time-based detection (optional)
- Common parameter testing

## Installation

```bash
git clone https://github.com/jrabbit00/roger-sqli.git
cd roger-sqli
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 sqli.py https://target.com/product?id=1

# Save results
python3 sqli.py target.com -o findings.txt
```

## What It Tests

- Error-based SQLi
- UNION-based SQLi
- Boolean-based SQLi
- Time-based SQLi (SLEEP)
- Comment-based bypasses

## Important Notes

- SQLi is illegal without authorization
- Always check bug bounty scope
- Manual verification required
- Time-based tests can be slow

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger SQLi helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)