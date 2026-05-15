# Brute Force Detection – Splunk SPL

## Objective
Detect multiple failed authentication attempts from a single IP targeting a single user.

---

## Detection Logic

- One IP
- One user
- Multiple failed login attempts
- Indicates possible brute force attack

---

## Splunk Query

```spl
index=main "Failed password"
| rex "for (?<user>\S+) from (?<src_ip>\S+)"
| search NOT src_ip="127.0.0.1" AND NOT src_ip="::1"
| stats count as failed_attempts by user, src_ip
| where failed_attempts > 10
```

---

## Investigation Steps

1. Identify targeted user
2. Check if login was later successful
3. Verify if IP is internal or external
4. Check repeated attack timing patterns
5. Investigate related activity from same IP

---

## Severity
Medium → High

---

## MITRE ATT&CK Mapping
- T1110 – Brute Force

---

## Skills Demonstrated
- Splunk SPL
- Authentication Log Analysis
- Threat Detection
- Incident Investigation
- SOC Analysis
