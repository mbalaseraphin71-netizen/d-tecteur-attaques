import datetime
from fpdf import FPDF
from core.scoring import score_ip

class AfriKorePDF(FPDF):
    def header(self):
        self.set_fill_color(26, 36, 43)  # Bandeau supérieur corporate
        self.rect(0, 0, 210, 8, "F")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"AFRIKORE SECURITY SAS - Document Confidentiel - Page {self.page_no()}", align="C")

def generer_pdf_web(resultats_analyse, connexions_root, blacklist_impact, nom_log):
    """Génère le rapport d'audit au format PDF (Version épurée de tout caractère non-ASCII)."""
    pdf = AfriKorePDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # En-tête du document - Utilisation de Helvetica standard universel
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(26, 36, 43)
    pdf.cell(0, 10, "AFRIKORE SECURITY", ln=True, align="L")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, f"Date de l'audit : {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", ln=True, align="L")
    pdf.cell(0, 5, f"Infrastructure cible : {nom_log}", ln=True, align="L")
    pdf.ln(10)
    
    # Calcul du niveau de menace moyen pour l'infrastructure
    score_moyen = sum([d["score"] for d in resultats_analyse.values()]) / len(resultats_analyse) if resultats_analyse else 0
    
    if score_moyen >= 75:
        score_texte = "CRITIQUE / INFRASTRUCTURE VULNERABLE"
        r, g, b = 186, 45, 45
    elif score_moyen >= 45:
        score_texte = "ALERTE MODEREE"
        r, g, b = 214, 137, 16
    else:
        score_texte = "SECURISE / CONFORME"
        r, g, b = 46, 117, 89

    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 12, f" INDICE DE RISQUE GLOBAL DE L'INFRASTRUCTURE : {score_moyen:.1f}/100 ({score_texte})", fill=True, ln=True, align="C")
    pdf.ln(8)

    # Tableau récapitulatif des menaces
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Vecteurs de compromission identifies (IPv4 / IPv6) :", ln=True)
    pdf.ln(2)
    
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 235, 240)
    pdf.cell(95, 8, " Indicateur de Securite", border=1, fill=True)
    pdf.cell(45, 8, " Requetes Identifiees", border=1, fill=True, align="C")
    pdf.cell(50, 8, " Niveau d'Urgence", border=1, fill=True, align="C")
    pdf.ln()
    
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(95, 8, " Tentatives d'intrusion par Force Brute SSH", border=1)
    pdf.cell(45, 8, str(sum([d["tentatives"] for d in resultats_analyse.values()])), border=1, align="C")
    pdf.cell(50, 8, "Elevee" if score_moyen > 45 else "Faible", border=1, align="C")
    pdf.ln()
    
    pdf.cell(95, 8, " Paquets issus d'adresses IP sur Liste Noire", border=1)
    pdf.cell(45, 8, str(len(blacklist_impact)), border=1, align="C")
    pdf.cell(50, 8, "CRITIQUE" if blacklist_impact else "Aucune", border=1, align="C")
    pdf.ln()
    
    pdf.cell(95, 8, " Connexions d'acces privileges acceptees (Root)", border=1)
    pdf.cell(45, 8, str(len(connexions_root)), border=1, align="C")
    pdf.cell(50, 8, "CRITIQUE SYSTEME" if connexions_root else "Aucune", border=1, align="C")
    pdf.ln(12)

    # Journalisation détaillée des IP sources
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "1. Evaluation Specifique des Adresses IP Cibles (Dual-Stack)", ln=True)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font("Helvetica", "", 10)
    if not resultats_analyse:
        pdf.cell(0, 8, "Aucun comportement hostile recense.", ln=True)
    else:
        for ip, data in resultats_analyse.items():
            rafale_str = "[BURST DETECTED]" if data["est_rafale"] else ""
            root_str = "[ROOT TARGETED]" if data["cible_root"] else ""
            pdf.cell(0, 7, f" - Hote : {ip} | Score: {data['score']}/100 | Niveau: {data['niveau']} {rafale_str} {root_str}", ln=True)

    # Section Traçabilité des accès Root
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "2. Tracabilite des Acces Privileges Souverains (Root)", ln=True)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font("Courier", "", 9)
    if not connexions_root:
        pdf.cell(0, 8, "Aucune elevation ou connexion root acceptee dans ce fichier.", ln=True)
    else:
        for ligne in connexions_root:
            ligne_nettoyee = ligne.encode('ascii', 'ignore').decode('ascii')
            pdf.cell(0, 6, f"> {ligne_nettoyee[:95]}", ln=True)

    pdf.ln(10)
    pdf.set_fill_color(240, 242, 245)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(0, 7, "Avis de conformite AfriKore : Ce document est un livrable d'audit automatique independant. Les donnees de telemetrie reseau sont cryptographiquement protegees sur nos infrastructures souveraines.", border=1, fill=True)

    # CORRECTION : Transformation directe en bloc de bytes pour le serveur Streamlit
    return bytes(pdf.output(dest="S"))
