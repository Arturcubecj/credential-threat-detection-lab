# Threat model

## Assets
SSH access to the victim server and the credentials of `labuser`.

## Techniques in scope (MITRE ATT&CK)
| Technique | ID | How it appears in the lab |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Many failed logins for one account from one IP |
| Brute Force: Password Spraying | T1110.003 | A few attempts against many usernames |
| Phishing | T1566 | Fake "account will be locked" email in the local inbox |
| Valid Accounts | T1078 | Login with a credential obtained by phishing |

## Baseline weaknesses (round 1)
| Weakness | Risk | Control (round 2) |
|---|---|---|
| SSH accepts passwords | High | Keys + TOTP (`hardening/`) |
| Weak password on `labuser` | High | Password policy |
| No limit on failed attempts | High | Wazuh active response + fail2ban |
| User not trained on phishing | High | Awareness, phishing-resistant MFA |
| Root login allowed, SSH open to whole subnet | Medium | `PermitRootLogin no`, ufw allowlist |

## Out of scope
Real users, real domains, malware, exploitation of software vulnerabilities, any host outside 192.168.100.0/24.
