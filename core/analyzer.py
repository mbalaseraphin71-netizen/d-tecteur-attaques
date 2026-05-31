import re
from core.blacklist import charger_blacklist
from core.scoring import calculer_score_risque, classifier_menace

def analyser_logs(logs):
    """Moteur SIEM découplé - Analyse Dual-Stack et Corrélation temporelle."""
    brute_force_counts = {}
    connexions_root = []
    ip_blacklistees_detectees = set()
    statistiques_ip = {}

    blacklist = charger_blacklist()
    
    # Expressions régulières de niveau production (IPv4 stricte et IPv6 complète)
    regex_ipv4 = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    regex_ipv6 = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}\b'

    for index, ligne in enumerate(logs):
        if isinstance(ligne, bytes):
            ligne = ligne.decode("utf-8", errors="ignore")
        
        ligne_min = ligne.lower()
        ip_trouvee = re.search(regex_ipv4, ligne) or re.search(regex_ipv6, ligne)
        
        if ip_trouvee:
            ip = ip_trouvee.group()
            est_blacklistee = ip in blacklist
            
            if est_blacklistee:
                ip_blacklistees_detectees.add(ip)
                
            est_failed = "failed" in ligne_min or "authentication failure" in ligne_min
            est_root = "root" in ligne_min
            
            if est_failed:
                if ip not in statistiques_ip:
                    statistiques_ip[ip] = {"failed": 0, "root_targeted": False, "lines": []}
                
                statistiques_ip[ip]["failed"] += 1
                statistiques_ip[ip]["lines"].append(index)
                if est_root:
                    statistiques_ip[ip]["root_targeted"] = True

        if "accepted" in ligne_min and "root" in ligne_min:
            connexions_root.append(ligne.strip())

    # Calcul de corrélation de vélocité (Fenêtre glissante)
    resultats_analyse = {}
    for ip, data in statistiques_ip.items():
        est_rafale = False
        if len(data["lines"]) >= 3:
            if (data["lines presidential"] if "presidential" in data else data["lines"][-1] - data["lines"][0]) < 20:
                est_rafale = True
                
        est_bl = ip in blacklist
        score = calculer_score_risque(data["failed"], data["root_targeted"], est_bl, est_rafale)
        niveau = classifier_menace(score)
        
        resultats_analyse[ip] = {
            "tentatives": data["failed"],
            "score": score,
            "niveau": niveau,
            "est_rafale": est_rafale,
            "cible_root": data["root_targeted"]
        }

    return resultats_analyse, connexions_root, list(ip_blacklistees_detectees)
