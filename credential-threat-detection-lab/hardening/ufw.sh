#!/usr/bin/env bash
# Host firewall for the victim server (round 2). Run as root inside the lab VM only.
set -euo pipefail
ufw --force reset
ufw default deny incoming
ufw default allow outgoing                         # agent -> manager on 1514/1515 is outbound
ufw allow from 192.168.100.50 to any port 22 proto tcp   # SSH only from the admin workstation
ufw --force enable
ufw status verbose
