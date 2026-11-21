# Roadmap

- **v0.1 (this release):** architecture, threat model, Wazuh rules, active response, hardening, Python detector with tests and CI.
- **v0.2:** run rounds 1 and 2 in the lab, fill `test-plan.md` with observed metrics and screenshots; add a Wazuh rule for password spraying; validate all rules with `wazuh-logtest`.
- **v0.3:** compare detection time and false positives across thresholds; export alerts and chart round 1 vs round 2.
- **Ideas:** phishing-resistant MFA (FIDO2) test, Suricata network IDS, using an LLM to triage and summarise Wazuh alerts with a human in the loop.
