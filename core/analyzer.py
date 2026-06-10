import re
import uuid
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from core.blacklist import charger_blacklist
from core.scoring import calculer_score_risque, classifier_menace


# ==============================================================================
# 1. MODÈLES DE DONNÉES ÉVÉNEMENTIELS
# ==============================================================================

class ActionType(Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    ROOT_ACCESS = "root_access"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    SSH = "ssh"
    UNKNOWN = "unknown"


def generate_event_id() -> str:
    """Génère un identifiant unique de traçabilité cyber par événement."""
    return f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


@dataclass
class SecurityEvent:
    timestamp: Optional[datetime]
    source_ip: str
    user: str
    action: ActionType
    service: ServiceType
    raw_line: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=generate_event_id)


# ==============================================================================
# 2. PARSER GESTIONNAIRE DU PROTOCOLE SSH
# ==============================================================================

class BaseParser:
    def validate_ip(self, ip: str) -> bool:
        """Validation réseau stricte via la bibliothèque native ipaddress."""
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

    def parse_timestamp(self, ts: Optional[str]) -> datetime:
        if not ts:
            return datetime.now()

        year = datetime.now().year
        formats = [
            "%b %d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S"
        ]

        for fmt in formats:
            try:
                if "%Y" not in fmt:
                    return datetime.strptime(f"{year} {ts}", f"{year} {fmt}")
                return datetime.strptime(ts, fmt)
            except Exception:
                continue

        return datetime.now()


class SSHLogParser(BaseParser):
    def __init__(self):
        # Signature de capture OpenSSH unifiée (supporte les PID système et dates)
        self.pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*'
            r'sshd(?:\[\d+\]|:).*'
            r'(Failed password for (?P<fail_user>\S+)|'
            r'Invalid user (?P<invalid_user>\S+)|'
            r'Accepted .* for (?P<ok_user>\S+)).*'
            r'from (?P<ip>[\da-fA-F\.:]+).*port (?P<port>\d+)'
        )

    def parse(self, line: str) -> Optional[SecurityEvent]:
        if not line:
            return None

        m = self.pattern.search(line)
        if not m:
            return None

        ip = m.group("ip")
        if not self.validate_ip(ip):
            return None

        user = (
            m.group("fail_user")
            or m.group("invalid_user")
            or m.group("ok_user")
            or "unknown"
        )

        is_success = m.group("ok_user") is not None

        # Détermination stricte du type d'action cyber
        if is_success and user == "root":
            action = ActionType.ROOT_ACCESS
        elif is_success:
            action = ActionType.AUTH_SUCCESS
        else:
            action = ActionType.AUTH_FAILURE

        port = int(m.group("port")) if m.group("port").isdigit() else 0

        return SecurityEvent(
            timestamp=self.parse_timestamp(m.group("timestamp")),
            source_ip=ip,
            user=user,
            action=action,
            service=ServiceType.SSH,
            raw_line=line,
            metadata={"port": port}
        )


class ParserRouter:
    def __init__(self):
        self.parsers = [SSHLogParser()]

    def parse(self, line: str) -> Optional[SecurityEvent]:
        for p in self.parsers:
            ev = p.parse(line)
            if ev:
                return ev
        return None


# ==============================================================================
# 3. DETECTEUR DE BURST (MÉMOIRE BORNÉE CYBER)
# ==============================================================================

class BurstDetector:
    def __init__(self, window=60, threshold=3, max_size=500):
        self.window = timedelta(seconds=window)
        self.threshold = threshold
        # maxlen=500 protège le serveur contre la saturation de la RAM
        self.data = defaultdict(lambda: deque(maxlen=max_size))

    def analyze(self, event: SecurityEvent) -> Dict[str, Any]:
        dq = self.data[event.source_ip]
        dq.append(event.timestamp)

        # Nettoyage de la fenêtre glissante temporelle (60 secondes)
        while dq and (event.timestamp - dq[0]) > self.window:
            dq.popleft()

        count = len(dq)

        return {
            "is_burst": count >= self.threshold,
            "event_count": count
        }


# ==============================================================================
# 4. PROFILER D'ÉTATS TECHNIQUES COMPORTEMENTAUX
# ==============================================================================

class IPProfiler:
    def __init__(self):
        self.profiles = defaultdict(self._new)

    def _new(self):
        return {
            "fail": 0,
            "success": 0,
            "root_targeted": False,
            "root_success": False,
            "users": set()
        }

    def update(self, event: SecurityEvent):
        p = self.profiles[event.source_ip]

        if event.action == ActionType.AUTH_FAILURE:
            p["fail"] += 1
            if event.user == "root":
                p["root_targeted"] = True

        elif event.action == ActionType.AUTH_SUCCESS:
            p["success"] += 1

        elif event.action == ActionType.ROOT_ACCESS:
            p["root_success"] = True

        p["users"].add(event.user)
        return p


# ==============================================================================
# 5. MOTEUR CENTRAL SIEM ET GESTIONNAIRE DU PIPELINE
# ==============================================================================

class SIEMEngine:
    def __init__(self):
        self.router = ParserRouter()
        self.profiler = IPProfiler()
        self.burst = BurstDetector()

        raw_bl = charger_blacklist()
        self.blacklist = set(raw_bl or [])

        self.results = {}
        self.root_success_lines = []
        self.blacklist_detected = set()

    def ingest(self, line: str):
        ev = self.router.parse(line)
        if not ev:
            return None

        profile = self.profiler.update(ev)
        burst = self.burst.analyze(ev)

        if ev.action == ActionType.ROOT_ACCESS:
            self.root_success_lines.append(ev.raw_line)

        is_blacklisted = ev.source_ip in self.blacklist
        if is_blacklisted:
            self.blacklist_detected.add(ev.source_ip)

        # Liaison avec le modèle mathématique pondéré logarithmique officiel
        score = calculer_score_risque(
            nb_tentatives=profile["fail"],
            est_root=profile["root_targeted"],
            est_blacklistee=is_blacklisted,
            est_rafale=burst["is_burst"],
            connexion_root_reussie=profile["root_success"]
        )

        # Alignement total des clés de sortie attendues par app.py et pdf_report.py
        self.results[ev.source_ip] = {
            "tentatives": profile["fail"],
            "score": score,
            "niveau": classifier_menace(score),
            "est_rafale": burst["is_burst"],
            "cible_root": profile["root_targeted"],
            "succes_root": profile["root_success"]
        }

        return ev


# ==============================================================================
# POINT D'ENTRÉE DU PACKAGE EXTRAC-INJECT
# ==============================================================================

def analyser_logs(logs):
    engine = SIEMEngine()

    for line in logs:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="ignore")
        engine.ingest(line)

    return engine.results, engine.root_success_lines, list(engine.blacklist_detected)


# ==============================================================================
# BLOC DE TEST DE CONFORMITÉ
# ==============================================================================
if __name__ == "__main__":
    logs_test = [
        "Jun 09 10:00:01 server sshd[123]: Failed password for root from 192.168.1.50 port 2222",
        "Jun 09 10:00:02 server sshd[123]: Failed password for root from 192.168.1.50 port 2222",
        "Jun 09 10:00:03 server sshd[123]: Accepted password for root from 192.168.1.50 port 2222"
    ]

    res, roots, bl = analyser_logs(logs_test)
    print("[-] Statut Architecture SIEM AfriKore v2.5 : PRODUCTION ACTIVE.")
    print(res)
