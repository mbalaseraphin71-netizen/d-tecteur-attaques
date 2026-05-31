import os

def charger_blacklist():
    """Charge dynamiquement les adresses IP compromises (IPv4 et IPv6)."""
    blacklist_locale = []
    nom_fichier = "blacklist.txt"
    
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            for ligne in f:
                ip = ligne.strip()
                if ip and not ip.startswith("#"):
                    blacklist_locale.append(ip)
    else:
        # Données de secours initiales (IPv4 & IPv6 de test)
        blacklist_locale = [
            "192.168.1.50", "45.75.12.3", "185.220.101.5",
            "2001:db8:85a3:8d3:1319:8a2e:370:7348", "fe80::1"
        ]
        
    return blacklist_locale
