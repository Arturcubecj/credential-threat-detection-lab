# MFA for SSH (key + TOTP)

1. On the victim server: `sudo apt install libpam-google-authenticator`.
2. As each allowed user, run `google-authenticator` and enrol the code in an authenticator app.
3. In `/etc/pam.d/sshd` add `auth required pam_google_authenticator.so` and comment out `@include common-auth`
   so the password prompt is not used.
4. Apply `sshd_99-hardening.conf` (it sets `AuthenticationMethods publickey,keyboard-interactive`).
5. Keep an open session while you test the new login in a second terminal.

**Limitation:** TOTP does not stop real-time phishing proxies (AiTM) that relay the code. Phishing-resistant
factors (FIDO2/WebAuthn security keys) are the recommendation for production; see `docs/roadmap.md`.
