def calculer_score_risque(nb_tentatives, est_root, est_blacklistee, est_rafale):
    """Calcule un score de risque pondéré (SIEM Grade) de 0 à 100."""
    score = 0
    
    # Facteur 1 : Fréquence des tentatives (Max 40 points)
    score += min(nb_tentatives * 4, 40)
    
    # Facteur 2 : Ciblage de privilèges critiques (Max 20 points)
    if est_root:
        score += 20
        
    # Facteur 3 : Corrélation avec la Threat Intelligence (Max 25 points)
    if est_blacklistee:
        score += 25
        
    # Facteur 4 : Vélocité de l'attaque / Burst (Max 15 points)
    if est_rafale:
        score += 15
        
    return min(score, 100)

def classifier_menace(score):
    """Classifie le niveau d'urgence selon le score pondéré."""
    if score >= 75:
        return "CRITIQUE"
    elif score >= 50:
        return "ÉLEVÉ"
    elif score >= 25:
        return "SUSPECT"
    return "FAIBLE"

def score_ip(nb_failed):
    """
    Fonction de compatibilité historique requise par le module d'exportation PDF.
    Renvoie directement le niveau textuel basé sur le volume d'échecs simples.
    """
    if nb_failed >= 10:
        return "CRITIQUE"
    elif nb_failed >= 5:
        return "ÉLEVÉ"
    elif nb_failed >= 3:
        return "SUSPECT"
    return "FAIBLE"
