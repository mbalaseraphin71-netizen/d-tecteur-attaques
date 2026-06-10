import math

def calculer_score_risque(
    nb_tentatives,
    est_root=False,
    est_blacklistee=False,
    est_rafale=False,
    connexion_root_reussie=False
):
    """
    Calcule le score d'indice de risque AfriKore (Modèle Pondéré Logarithmique v2.0).
    Échelle : 0 à 100 points maximum.
    """
    score = 0

    # 1. Fréquence logarithmique des attaques (Max : 40 points)
    if nb_tentatives > 0:
        score += min(math.log2(nb_tentatives + 1) * 10, 40)

    # 2. Tentative de forçage sur compte root (Max : 20 points)
    if est_root:
        score += 20

    # 3. IP répertoriée dans la Threat Intelligence / Blacklist (Max : 25 points)
    if est_blacklistee:
        score += 25

    # 4. Détection de rafale / Vélocité Burst (Max : 15 points)
    if est_rafale:
        score += 15

    # 5. BONUS CRITIQUE : Corrélation de connexion Root acceptée (+30 points)
    if connexion_root_reussie:
        score += 30

    # 6. CORRÉLATIONS DANGEREUSES COMBINÉES
    if est_root and est_blacklistee:
        score += 10

    if est_blacklistee and est_rafale:
        score += 5

    return min(round(score, 1), 100)


def classifier_menace(score):
    """Classification officielle de la matrice de menace AfriKore."""
    if score >= 75:
        return "CRITIQUE"
    elif score >= 50:
        return "ÉLEVÉ"
    elif score >= 25:
        return "SUSPECT"
    return "FAIBLE"


def score_ip(nb_failed):
    """Compatibilité unifiée utilisant le moteur de calcul principal."""
    score = calculer_score_risque(nb_tentatives=nb_failed)
    return classifier_menace(score)
