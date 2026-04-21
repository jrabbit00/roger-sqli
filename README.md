# Roger SQLi 🐰

SQL injection vulnerability scanner for bug bounty hunting. Tests for SQLi in web applications.

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

## License

MIT License