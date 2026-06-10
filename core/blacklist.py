import os
import ipaddress
from typing import Set, List

def charger_blacklist() -> List[str]:
    """
    Fonction globale de compatibilité historique.
    Permet aux autres modules d'appeler la liste brute d'IP.
    """
    manager = BlacklistManager()
    return list(manager.blacklist)


class BlacklistManager:
    def __init__(self, fichier: str = "blacklist.txt", seuil: int = 80):
        self.fichier = fichier
        self.seuil = seuil
        self.blacklist: Set[str] = self._charger()

    def _charger(self) -> Set[str]:
        """Charge la liste noire d'IP, valide chaque entrée et crée le fichier s'il est absent."""
        ips = set()
        if os.path.exists(self.fichier):
            with open(self.fichier, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        # Validation réseau stricte (IPv4 / IPv6)
                        try:
                            ipaddress.ip_address(ip)
                            ips.add(ip)
                        except ValueError:
                            pass
        else:
            # CORRECTION 2 : Initialisation et persistance immédiate du fichier s'il n'existe pas
            ips = {
                "192.168.1.50", "45.75.12.3", "185.220.101.5",
                "2001:db8:85a3:8d3:1319:8a2e:370:7348", "fe80::1"
            }
            try:
                with open(self.fichier, "w", encoding="utf-8") as f:
                    f.write("# --- LISTE NOIRE D'URGENCE AFRIKORE SECURITY ---\n")
                    for ip in sorted(ips):
                        f.write(ip + "\n")
            except Exception:
                pass
                
        return ips

    def is_blacklisted(self, ip: str) -> bool:
        """Vérification immédiate en complexité O(1) via la table de hachage."""
        return ip in self.blacklist

    def evaluate_and_add(self, ip: str, score: float) -> bool:
        """
        CORRECTION 1 : Vérifie la validité de l'IP avant l'auto-ban, 
        puis l'ajoute dynamiquement si le score est critique.
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False

        if score >= self.seuil and ip not in self.blacklist:
            self.blacklist.add(ip)
            self._persist(ip)
            return True

        return False

    def _persist(self, ip: str):
        """Inscrit de force l'IP bannie dans blacklist.txt sans créer de doublons."""
        try:
            if os.path.exists(self.fichier):
                with open(self.fichier, "r", encoding="utf-8") as f:
                    if ip in [line.strip() for line in f]:
                        return
            with open(self.fichier, "a", encoding="utf-8") as f:
                f.write(ip + "\n")
        except Exception:
            pass
