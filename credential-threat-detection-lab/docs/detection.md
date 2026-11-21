# Detection engineering

| Rule | Wazuh ID | Python rule | Logic | ATT&CK | Level |
|---|---|---|---|---|---|
| Brute force | 100100 | `ssh_brute_force` | ≥5 failures, same source IP, 60 s | T1110.001 | 10 |
| Password spraying | — (v0.2) | `ssh_password_spraying` | ≥4 distinct users, same IP, 60 s | T1110.003 | 10 |
| Non-allowlisted login | 100101 | `ssh_login_unauthorized_source` | SSH success from IP ≠ 192.168.100.50 | T1078 | 12 |
| Success after failures | 100102 | `ssh_success_after_failures` | Success after a brute-force alert from the same IP | T1078 | 13 |

## Why two implementations
The Wazuh rules are what runs in the lab. The Python detector (`detector/`) reproduces the same logic so it can
be unit-tested in CI against synthetic logs before touching the SIEM, and so thresholds can be tuned quickly.

## Key insight
The SIEM never sees the phishing email. It sees the *consequence*: a valid login from a source that should not
be logging in. That is why the allowlist rule (100101) matters as much as the brute-force rule.

## Validating the Wazuh rules
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste lines from samples/auth_round1_synthetic.log one by one and check the rule id that fires
```
