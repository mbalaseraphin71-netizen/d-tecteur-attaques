#  AfriKore Security : African Cyber Defense Framework & Log Analyzer

<p align="center">
  <img src="https://shields.io" alt="Python Version">
  <img src="https://shields.io" alt="Streamlit">
  <img src="https://shields.io" alt="Security Level">
  <img src="https://shields.io" alt="Sovereign Infrastructure">
</p>

---

##  Project Overview
**AfriKore Security** is an automated cybersecurity web application developed in Python. It parses and analyzes network server logs (such as SSH logs) to detect malicious activities in real time. The engine automates threat detection (Brute Force, privilege escalation) and generates production-ready, downloadable PDF security compliance reports.

This software repository serves as a practical engineering validation for **Cybersecurity & Sovereign Digital Infrastructure - Level L1**.

---

## 🚀 Core Features (L1 Operational Version)

###  Threat Intelligence & Heuristic Analysis
*   **SSH Brute Force Detection**: Automatic extraction of source IPv4 addresses attempting repetitive unauthorized access.
*   **Invalid Profiling Filtering**: Automated isolation of connections originating from unregistered or illegal usernames.
*   **Privilege Escalation Monitoring**: Critical tracking and tracking of successful `root` access logs.
*   **Dynamic Reputation Control**: Real-time cross-referencing of extracted IPs against a localized threat intelligence blacklist (`blacklist.txt`).

### Modern Web UI Engine (Streamlit)
*   **Interactive Dashboard**: High-level security metrics displayed via responsive, color-coded scorecards.
*   **Multi-Log Processing**: Drag & Drop upload container supporting concurrent processing of multiple `.log` or `.txt` dumps.

###  Automated Compliance Reporting
*   **Native PDF Generator**: One-click generation of an incident response report without encoding errors (powered by `fpdf2`).
*   **Risk Classification**: Automated tagging of suspicious machines by threat score (SUSPECT / DANGER-ATTACK).

---

##  Detection Thresholds & Logic

*   **Brute Force Threshold**: Triggered automatically when an IP matches $\ge 3$ failed password attempts (`failed password`).
*   **Syntax & Parsing Rules**: High-fidelity IPv4 extraction built entirely on native Regular Expressions (`re` module).
*   **Sovereign Logic**: Configured to work in air-gapped or localized environments without relying on third-party cloud infrastructure.

---

##  Technology Stack

*   **Language**: Python 3.14+
*   **Framework UI**: Streamlit (Cloud & Local Architecture)
*   **PDF Core Engine**: fpdf2 (Robust corporate reporting)
*   **Pattern Matching**: Native Python Regular Expressions (`re`)

---

##  Installation & Local Deployment

### 1. Clone the repository
```bash
git clone https://github.com
cd AfriKore-Security
```

### 2. Install dependencies
Install the required production packages specified in the environment file:
```bash
pip install -r requirements.txt
```

### 3. Run the application
Launch the local Streamlit server using the Python module execution flag:
```bash
python -m streamlit run Detecteur_Web.py
```

---

##  Strategic Venture Roadmap (L1 to L5 Enterprise Goal)

*   [x] **Phase L1 (Current)**: Core parsing engine stabilization, dynamic local blacklisting, and production web deployment.
*   [ ] **Phase L2**: Implementation of a cryptographically secure user authentication module, relational database (PostgreSQL) logging history, and VirusTotal Threat Intelligence API hooks.
*   [ ] **Phase L3**: Architecture containerization via Docker, live packet monitoring (real-time traffic analysis), and ML-driven network anomaly detection.
*   [ ] **Phase L4 - L5**: Enterprise scaling, deployment on sovereign African servers, infrastructure auditing, and full commercialization of the **AfriKore Security Suite**.

---
*« Protect Content, Empower Sovereign Infrastructure »*  
**Engineered with absolute rigor by Séraphin Mbala** | Future Cybersecurity Engineer © 2026
