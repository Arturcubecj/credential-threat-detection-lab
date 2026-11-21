# Test plan

Status: **planned**. No lab results yet; the "Observed" column is filled in after each round.

| # | Scenario | Round | Expected | Observed |
|---|---|---|---|---|
| 1 | Password-guessing test against `labuser` over SSH | 1 (detect only) | Alert 100100 within seconds; attempts continue | _pending_ |
| 2 | Same as 1 | 2 (controls on) | Source IP blocked by active response; password auth refused | _pending_ |
| 3 | Phishing email → credential entered → SSH login with it | 1 | Login succeeds; alerts 100101 and 100102 | _pending_ |
| 4 | Same as 3 | 2 | Login fails (key + TOTP required, ufw allowlist) | _pending_ |
| 5 | Admin login from 192.168.100.50 | 1 and 2 | No alert (false-positive check) | _pending_ |

## Metrics
- Failed attempts tolerated before the first alert / before the block
- Time from first attempt to alert (dashboard timestamp minus first log line)
- Whether the attacker obtains a shell (yes/no)
- False positives during the session
