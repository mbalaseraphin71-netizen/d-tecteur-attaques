import streamlit as st

try:
    from core.analyzer import analyser_logs
    from export.pdf_report import generer_pdf_web
except ImportError as e:
    st.error(f"❌ Erreur d'importation : Modules d'arrière-plan introuvables. Trace : {e}")
    st.stop()

st.set_page_config(
    page_title="AfriKore Security - SIEM Console",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 AfriKore Security - SIEM Console")
st.caption("Interface utilisateur — Couche présentation uniquement [Version Modulaire v2.5]")

uploaded_files = st.file_uploader(
    "Importer des fichiers logs (auth.log, access.log)",
    type=["log", "txt"],
    accept_multiple_files=True
)

if uploaded_files:
    for file in uploaded_files:
        st.divider()
        st.subheader(f"📄 Analyse en cours : {file.name}")

        try:
            logs = file.readlines()
            analysis, roots, blacklist = analyser_logs(logs)

            col1, col2, col3 = st.columns(3)
            total_critiques = sum([1 for d in analysis.values() if d["niveau"] == "CRITIQUE"])

            col1.metric("Hôtes détectés", len(analysis), delta=f"{total_critiques} Critiques" if total_critiques else "RAS", delta_color="inverse")
            col2.metric("IPs blacklistées", len(blacklist))
            col3.metric("Accès root", len(roots), delta="Alerte privilèges" if roots else "RAS", delta_color="inverse")

            st.subheader("📊 Résultats de sécurité")
            if not analysis:
                st.success("✅ Aucun comportement malveillant ou signature d'attaque détectés.")
            else:
                for ip, data in analysis.items():
                    version_ip = "IPv6" if ":" in ip else "IPv4"
                    label = f"🌐 Hôte {version_ip} : {ip} | Score : {data['score']}/100 | Niveau : {data['niveau']}"
                    
                    if data["est_rafale"]:
                        label += " ⚡ [Attaque par Rafale / Burst]"
                    if data["cible_root"]:
                        label += " ⚠️ [Cible Privilège / Root]"

                    if data["niveau"] == "CRITIQUE":
                        st.error(label)
                    elif data["niveau"] == "ÉLEVÉ":
                        st.warning(label)
                    else:
                        st.info(label)

            st.subheader("🔑 Accès privilégiés")
            if roots:
                for r in roots:
                    st.code(r[:110] + "..." if len(r) > 110 else r, language="bash")
            else:
                st.success("Aucun accès root détecté.")

            try:
                pdf_data = generer_pdf_web(analysis, roots, blacklist, file.name)
                st.download_button(
                    label="📥 Télécharger rapport PDF",
                    data=pdf_data,
                    file_name=f"afrikore_report_{file.name}.pdf",
                    mime="application/pdf"
                )
            except Exception as e_pdf:
                st.error(f"Erreur d'export PDF : {e_pdf}")
                
        except Exception as e_global:
            st.error(f"Erreur lors de la lecture du fichier journal : {e_global}")

with st.sidebar:
    st.title("AfriKore SIEM")
    st.markdown(
        """
        - UI Layer uniquement  
        - Logique externalisée (core/)  
        - Export indépendant  
        - Détection Dual-Stack IPv4 / IPv6
        - Corrélation temporelle active
        ---
        **© 2026 — Séraphin Mbala**
        """
    )
