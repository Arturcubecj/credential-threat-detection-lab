"""Sliding-window detections for brute force, password spraying and account compromise."""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, List


@dataclass
class DetectorConfig:
    window: timedelta = timedelta(seconds=60)
    brute_force_threshold: int = 5        # failures from one IP inside the window
    spray_distinct_users: int = 4         # distinct usernames from one IP inside the window
    compromise_lookback: timedelta = timedelta(minutes=10)
    compromise_min_failures: int = 3      # failures before a success that make it suspicious
    allowed_sources: List[str] = field(default_factory=list)  # IPs/CIDRs allowed to log in

    def is_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(net, strict=False) for net in self.allowed_sources)


@dataclass(frozen=True)
class Alert:
    rule: str
    mitre: str
    severity: int
    src_ip: str
    user: str
    timestamp: str
    detail: str


def detect(events: Iterable, cfg: DetectorConfig | None = None) -> List[Alert]:
    cfg = cfg or DetectorConfig()
    alerts: List[Alert] = []
    failures = defaultdict(deque)          # ip -> deque[(ts, user)]
    fired_bf, fired_spray = {}, {}         # ip -> ts of last alert (de-duplication per window)

    for ev in sorted(events, key=lambda e: e.timestamp):
        q = failures[ev.src_ip]
        horizon = max(cfg.window, cfg.compromise_lookback)
        while q and ev.timestamp - q[0][0] > horizon:
            q.popleft()

        if ev.outcome == "failure":
            q.append((ev.timestamp, ev.user))
            in_window = [(t, u) for t, u in q if ev.timestamp - t <= cfg.window]

            last = fired_bf.get(ev.src_ip)
            if len(in_window) >= cfg.brute_force_threshold and (last is None or ev.timestamp - last > cfg.window):
                fired_bf[ev.src_ip] = ev.timestamp
                alerts.append(Alert("ssh_brute_force", "T1110.001", 10, ev.src_ip, ev.user, ev.timestamp.isoformat(),
                                    f"{len(in_window)} failed logins in {int(cfg.window.total_seconds())}s"))

            users = {u for _, u in in_window}
            last = fired_spray.get(ev.src_ip)
            if len(users) >= cfg.spray_distinct_users and (last is None or ev.timestamp - last > cfg.window):
                fired_spray[ev.src_ip] = ev.timestamp
                alerts.append(Alert("ssh_password_spraying", "T1110.003", 10, ev.src_ip, ev.user, ev.timestamp.isoformat(),
                                    f"{len(users)} distinct users targeted in {int(cfg.window.total_seconds())}s"))
        else:
            prior = [t for t, _ in q if ev.timestamp - t <= cfg.compromise_lookback]
            if len(prior) >= cfg.compromise_min_failures:
                alerts.append(Alert("ssh_success_after_failures", "T1078", 12, ev.src_ip, ev.user, ev.timestamp.isoformat(),
                                    f"login succeeded after {len(prior)} failures from the same IP"))
            if cfg.allowed_sources and not cfg.is_allowed(ev.src_ip):
                alerts.append(Alert("ssh_login_unauthorized_source", "T1078", 12, ev.src_ip, ev.user, ev.timestamp.isoformat(),
                                    "successful login from a source outside the allowlist"))
    return alerts
