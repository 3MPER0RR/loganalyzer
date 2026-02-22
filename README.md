# LogAnalyzer

LogAnalyzer is a lightweight CLI forensic tool written in Perl for analyzing SSH authentication logs.

It parses standard Linux SSH log files (e.g. `auth.log` or `secure`) and detects suspicious activity such as repeated failed login attempts.

---

## Features

- Parses SSH authentication logs
- Counts failed login attempts per IP
- Detects successful logins
- Highlights suspicious IPs exceeding a configurable threshold
- Simple single-file implementation

---

## Supported Log Formats

Designed for standard Linux SSH logs:

- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (CentOS/RHEL)

---

## Usage

```bash
perl log_audit.pl <logfile>
