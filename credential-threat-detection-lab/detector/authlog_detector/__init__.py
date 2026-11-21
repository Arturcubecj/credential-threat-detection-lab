"""Offline detector for credential attacks in OpenSSH auth logs.

It mirrors the Wazuh rules in ../wazuh/rules so the detection logic can be
unit-tested without a running SIEM.
"""
from .parser import AuthEvent, parse_line, parse_lines
from .detector import Alert, DetectorConfig, detect

__all__ = ["AuthEvent", "parse_line", "parse_lines", "Alert", "DetectorConfig", "detect"]
__version__ = "0.1.0"
