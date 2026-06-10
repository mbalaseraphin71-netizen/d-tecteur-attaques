import pandas as pd
import streamlit as st

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
st.caption("Interface Utilisateur — Couche Présentation Unique [Version Modulaire v2.5]")

uploaded_files = st.file_uploader(
    "Importer des fichiers logs d'infrastructure (auth.log, access.log)",
    type=["log", "txt"],
    accept_multiple_files=True
)

if uploaded_files:
    for file in uploaded_files:
        st.divider()
        st.subheader(f"📄 Analyse en cours du périmètre : `{file.name}`")

        # SÉCURITÉ STREAMLIT (Limite physique de téléversement)
        if file.size > 50 * 1024 * 1024:  # Limite stricte à 50 Mo
            st.error(f"❌ Échec de l'ingestion : Le fichier `{file.name}` est trop volumineux (> 50 Mo).")
            continue

        try:
            # LIMITATION DES LOGS TRÈS VOLUMINEUX
            MAX_LINES = 100000
            toutes_les_lignes = file.readlines()
            logs = toutes_les_lignes[:MAX_LINES]
            
            if len(toutes_les_lignes) > MAX_LINES:
                st.warning(f"⚠️ Flux restreint : Le fichier contient {len(toutes_les_lignes)} lignes. Seules les {MAX_LINES} premières lignes ont été analysées.")

            # Appel direct au pipeline orienté objet durci
            analysis, roots, blacklist = analyser_logs(logs)

            # --- VOYANTS ET MÉTRIQUES COMPORTEMENTALES ---
            col1, col2, col3 = st.columns(3)
            total_critiques = sum([1 for d in analysis.values() if str(d.get("niveau", "")).upper() == "CRITIQUE"])

            col1.metric("Hôtes Hostiles Identifiés", len(analysis), delta=f"{total_critiques} Critiques" if total_critiques else "RAS", delta_color="inverse")
            col2.metric("IPs de la Blacklist Détectées", len(blacklist))
            col3.metric("Accès Root Validés", len(roots), delta="COMPROMISSION" if roots else "RAS", delta_color="inverse")

            # ==================================================================
            # 📊 REPRÉSENTATIONS GRAPHIQUES (L'IMPACT VISUEL SIEM)
            # ==================================================================
            if analysis:
                st.subheader("📈 Analytique Globale des Menaces")
                
                # Préparation des données pour Pandas (sans surcharger la RAM)
                chart_data = []
                for ip, data in analysis.items():
                    chart_data.append({
                        "Adresse IP": ip,
                        "Tentatives": data.get("tentatives", 0),
                        "Score": data.get("score", 0),
                        "Niveau": str(data.get("niveau", "")).upper()
                    })
                df = pd.DataFrame(chart_data)

                g1, g2 = st.columns(2)

                with g1:
                    st.write("**Top 10 des Hôtes les plus agressifs (Volume d'attaques)**")
                    # Tri et filtrage des 10 premières lignes
                    df_top_attacks = df.sort_values(by="Tentatives", ascending=False).head(10)
                    st.bar_chart(data=df_top_attacks, x="Adresse IP", y="Tentatives", color="#ba2d2d")

                with g2:
                    st.write("**Répartition des Niveaux de Danger Détectés**")
                    # Groupement par niveau de menace pour compter les occurrences
                    df_level_counts = df["Niveau"].value_counts()
                    st.bar_chart(df_level_counts, color="#d68910")
            
            # --- RENDU DE LA MATRICE DE RISQUES SANS SATURATION ---
            st.subheader("📊 Détail des Hôtes Suspects (Top 100 Critiques)")
            if not analysis:
                st.success("✅ Aucun comportement anormal ou signature d'attaque détectés sur ce flux.")
            else:
                ips_triees = sorted(
                    analysis.items(),
                    key=lambda x: x.get("score", 0),
                    reverse=True
                )
                
                for ip, data in ips_triees[:100]:
                    version_ip = "IPv6" if ":" in ip else "IPv4"
                    label = f"🌐 Hôte {version_ip} : {ip} | Score : {data.get('score', 0)}/100 | Niveau : {data.get('niveau', 'INCONNU')}"
                    
                    if data.get("est_rafale", False):
                        label += " ⚡ [Attaque par Rafale / Burst]"
                    if data.get("cible_root", False):
                        label += " ⚠️ [Cible Privilège / Root Targeted]"
                    if data.get("succes_root", False):
                        label += " 🚨 [ACCÈS PRIVILÈGE ACCEPTE]"

                    niveau = str(data.get("niveau", "")).upper()

                    if niveau == "CRITIQUE" or data.get("succes_root", False):
                        st.error(label)
                    elif niveau in ("ÉLEVÉ", "ELEVE"):
                        st.warning(label)
                    else:
                        st.info(label)

            # --- ZONE DE TRAÇABILITÉ DES INFRASTRUCTURES ---
            st.subheader("🔑 Traçabilité des Accès Privilégiés (Root)")
            if roots:
                for r in roots:
                    st.code(r[:110] + "..." if len(r) > 110 else r, language="bash")
            else:
                st.success("Aucune anomalie d'accès privilège constatée dans ce fichier.")

            # --- PIPELINE DE TÉLÉCHARGEMENT ET NETTOYAGE DU NOM ---
            try:
                pdf_data = generer_pdf_web(analysis, roots, blacklist, file.name)
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
        * Interface Graphique Native (`Pandas`)
        * Bornage Mémoire et Fichiers (<50 Mo)
        * Auto-Ban Réseau Persistant
        * Détection Dual-Stack IPv4 / IPv6
        ---
        **© 2026 — Séraphin Mbala**
        """
    )
