# Phishing simulation (awareness exercise)

Purpose: show that the SIEM detects the *use* of a stolen credential, and measure user behaviour.

## Rules of engagement
- Only the lab user VM (192.168.100.40) and fictitious mailboxes on a local MailHog instance.
- No real brand, institution, domain or person is imitated; the lure uses a fictitious "Lab IT Desk".
- The landing page lives inside the lab network and stores nothing outside it.

## Indicators taught after the exercise
Unexpected sender, false urgency ("your account will be locked in 48 h"), link domain that does not match the
organisation, request to "validate" a password, generic signature.

## Metrics
Email opened, link clicked, credential submitted, email reported to IT.
