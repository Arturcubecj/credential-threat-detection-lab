"""Parse OpenSSH (sshd) syslog lines into structured events."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# Example: "Nov 20 10:01:02 victim sshd[1234]: Failed password for invalid user admin from 192.168.100.10 port 50122 ssh2"
_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    outcome: str  # "failure" or "success"
    user: str
    src_ip: str
    method: str
    invalid_user: bool = False


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Return an AuthEvent for a relevant sshd line, or None."""
    m = _SYSLOG.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
    msg = m["msg"]
    if (f := _FAILED.match(msg)):
        return AuthEvent(ts, m["host"], "failure", f["user"], f["ip"], f["method"], "invalid user" in msg)
    if (a := _ACCEPTED.match(msg)):
        return AuthEvent(ts, m["host"], "success", a["user"], a["ip"], a["method"])
    # "Invalid user" lines duplicate the matching "Failed password" line, so they are skipped.
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        ev = parse_line(line, year)
        if ev is not None:
            yield ev
