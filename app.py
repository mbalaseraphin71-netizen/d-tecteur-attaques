import pandas as pd
import streamlit as st

# Vérification et routage sécurisé des importations depuis vos sous-modules
try:
    from core.analyzer import analyser_logs
    from export.pdf_report import generer_pdf_web
except ImportError as e:
    st.error(f"❌ Erreur critique d'infrastructure : Modules d'arrière-plan introuvables. Trace : {e}")
    st.stop()

# Configuration visuelle de la console AfriKore
st.set_page_config(
    page_title="AfriKore Security - SIEM Console",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 AfriKore Security - SIEM Console")
st.caption("Interface Utilisateur — Couche Présentation Unique [Version Industrielle Modulaire v2.5]")

# Ingestion des flux de journaux d'événements
uploaded_files = st.file_uploader(
    "Importer des fichiers logs d'infrastructure (auth.log, access.log)",
    type=["log", "txt"],
    accept_multiple_files=True
)

if uploaded_files:
    for file in uploaded_files:
        st.divider()
        st.subheader(f"📄 Analyse en cours du périmètre : `{file.name}`")

        # SÉCURITÉ STREAMLIT : Limite physique de téléversement pour protéger le serveur
        if file.size > 50 * 1024 * 1024:  # Limite stricte à 50 Mo
            st.error(f"❌ Échec de l'ingestion : Le fichier `{file.name}` est trop volumineux (> 50 Mo).")
            continue

        try:
            # BORNAGE MÉMOIRE : Limitation des fichiers de logs gigantesques
            MAX_LINES = 100000
            toutes_les_lignes = file.readlines()
            logs = toutes_les_lignes[:MAX_LINES]
            
            if len(toutes_les_lignes) > MAX_LINES:
                st.warning(f"⚠️ Flux restreint : Le fichier contient {len(toutes_les_lignes)} lignes. Seules les {MAX_LINES} premières lignes ont été analysées pour préserver les performances système.")

            # Appel direct au pipeline d'analyse orienté objet v2.5
            analysis, roots, blacklist = analyser_logs(logs)

            # --- PANNEAU DES VOYANTS ET MÉTRIQUES COMPORTEMENTALES ---
            col1, col2, col3 = st.columns(3)
            
            # Unpacking sécurisé préventif pour calculer le nombre d'alertes critiques
            total_critiques = 0
            for k, v in analysis.items():
                val_data = v[0] if isinstance(v, tuple) and len(v) > 0 else v
                if isinstance(val_data, dict) and str(val_data.get("niveau", "")).upper() == "CRITIQUE":
                    total_critiques += 1

            col1.metric("Hôtes Hostiles Identifiés", len(analysis), delta=f"{total_critiques} Critiques" if total_critiques else "RAS", delta_color="inverse")
            col2.metric("IPs de la Blacklist Détectées", len(blacklist))
            col3.metric("Accès Root Validés", len(roots), delta="COMPROMISSION" if roots else "RAS", delta_color="inverse")

            # ==================================================================
            # 📊 REPRÉSENTATIONS GRAPHIQUES (L'IMPACT VISUEL SIEM NATIVE PANDAS)
            # ==================================================================
            if analysis:
                st.subheader("📈 Analytique Globale des Menaces")
                
                chart_data = []
                for ip, raw_v in analysis.items():
                    # Unpacking de sécurité du tuple pour alimenter le DataFrame Pandas
                    data_clean = raw_v[0] if isinstance(raw_v, tuple) and len(raw_v) > 0 else raw_v
                    if isinstance(data_clean, dict):
                        chart_data.append({
                            "Adresse IP": ip,
                            "Tentatives": data_clean.get("tentatives", 0),
                            "Score": data_clean.get("score", 0),
                            "Niveau": str(data_clean.get("niveau", "INCONNU")).upper()
                        })
                
                if chart_data:
                    df = pd.DataFrame(chart_data)
                    g1, g2 = st.columns(2)

                    with g1:
                        st.write("**Top 10 des Hôtes les plus agressifs (Volume d'attaques)**")
                        df_top_attacks = df.sort_values(by="Tentatives", ascending=False).head(10)
                        st.bar_chart(data=df_top_attacks, x="Adresse IP", y="Tentatives", color="#ba2d2d")

                    with g2:
                        st.write("**Répartition des Niveaux de Danger Détectés**")
                        df_level_counts = df["Niveau"].value_counts()
                        st.bar_chart(df_level_counts, color="#d68910")
            
            # ==================================================================
            # 📊 RENDU SÉCURISÉ DE LA MATRICE DE RISQUES (TOP 100 MENACES)
            # ==================================================================
            st.subheader("📊 Détail des Hôtes Suspects (Top 100 Critiques)")
            if not analysis:
                st.success("✅ Aucun comportement anormal ou signature d'attaque détectés sur ce flux.")
            else:
                # ÉPAISSISSEMENT SÉCURITÉ : Reconstruction d'un dictionnaire d'objets purs (Unpack du Tuple)
                nettoyage_analyse = {}
                for cle_ip, valeur_raw in analysis.items():
                    if isinstance(valeur_raw, tuple) and len(valeur_raw) > 0:
                        nettoyage_analyse[cle_ip] = valeur_raw[0]
                    elif isinstance(valeur_raw, dict):
                        nettoyage_analyse[cle_ip] = valeur_raw
                    else:
                        nettoyage_analyse[cle_ip] = {
                            "tentatives": 0, "score": 0, "niveau": "INCONNU",
                            "est_rafale": False, "cible_root": False, "succes_root": False
                        }

                # Tri synchrone basé sur le dictionnaire d'octets purs nettoyés
                ips_triees = sorted(
                    nettoyage_analyse.items(),
                    key=lambda x: x[1].get("score", 0) if isinstance(x[1], dict) else 0,
                    reverse=True
                )
                
                for ip, data in ips_triees[:100]:
                    version_ip = "IPv6" if ":" in ip else "IPv4"
                    score_actuel = data.get("score", 0)
                    niveau_actuel = data.get("niveau", "INCONNU")
                    
                    label = f"🌐 Hôte {version_ip} : {ip} | Score : {score_actuel}/100 | Niveau : {niveau_actuel}"
                    
                    if data.get("est_rafale", False):
                        label += " ⚡ [Attaque par Rafale / Burst]"
                    if data.get("cible_root", False):
                        label += " ⚠️ [Cible Privilège / Root Targeted]"
                    if data.get("succes_root", False):
                        label += " 🚨 [ACCÈS PRIVILÈGE ACCEPTE]"

                    # Traitement de la robustesse face aux accents de casse
                    niveau = str(niveau_actuel).upper()

                    if niveau == "CRITIQUE" or data.get("succes_root", False):
                        st.error(label)
                    elif niveau in ("ÉLEVÉ", "ELEVE"):
                        st.warning(label)
                    else:
                        st.info(label)

            # --- ZONE DE TRAÇABILITÉ DES ACCÈS PRIVILÈGES SOUVERAINS ---
            st.subheader("🔑 Traçabilité des Accès Privilégiés (Root)")
            if roots:
                for r in roots:
                    st.code(r[:110] + "..." if len(r) > 110 else r, language="bash")
            else:
                st.success("Aucune anomalie d'accès privilège constatée dans ce fichier.")

            # --- PIPELINE DE TÉLÉCHARGEMENT COMPORTEMENTAL PDF (NETTOYAGE DU NOM) ---
            try:
                # Utilise le dictionnaire nettoyé pour alimenter le compilateur PDF
                pdf_data = generer_pdf_web(nettoyage_analyse, roots, blacklist, file.name)
                nom_base = file.name.rsplit(".", 1)[0]
                
                st.download_button(
                    label="📥 Télécharger le Rapport d'Audit Avancé PDF",
                    data=pdf_data,
                    file_name=f"afrikore_siem_report_{nom_base}.pdf",
                    mime="application/pdf"
                )
            except Exception as e_pdf:
                st.error(f"Erreur d'export du compilateur PDF : {e_pdf}")
                
        except Exception as e_global:
            st.error(f"Erreur lors du traitement analytique du fichier journal : {e_global}")

with st.sidebar:
    st.title("AfriKore SIEM Hub")
    st.markdown(
        """
        **Spécifications Cyber v2.5**
        * Interface Visuelle Native (`Pandas`)
        * Bornage Mémoire Étanche (<50 Mo)
        * Auto-Ban Réseau Persistant
        * Détection Dual-Stack IPv4 / IPv6
        ---
        **© 2026 — Séraphin Mbala**
        """
    )
