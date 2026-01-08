# wazuh-suricata-openvpn-lab

NGFW-Enhanced Wazuh SOC Homelab: Integrating Suricata IDS and OpenVPN for Network Anomaly Detection
January 2026 – Present
Cybersecurity Enthusiast | SLIIT Student
This project extends my core Wazuh SIEM homelab to incorporate next-generation firewall (NGFW) capabilities using open-source tools. By integrating Suricata for intrusion detection and OpenVPN for VPN simulation, I demonstrate hands-on skills in network monitoring, log ingestion, custom rule development, and alert triage—key for Tier 1 SOC analyst roles. This setup simulates real-world scenarios like impossible travel detection, aligning with MITRE ATT&CK techniques (e.g., T1078: Valid Accounts).
Project Highlights

Objective: Build an isolated homelab to practice SOC workflows: ingest multi-source logs (endpoint, network, VPN), create custom detection rules for anomalies, and triage alerts in Wazuh dashboard.
Key Achievements:
Ingested Suricata EVE JSON logs and OpenVPN syslog for centralized analysis, processing network flows and authentication events.
Developed custom Wazuh rules to detect impossible travel (e.g., same-user VPN + local logins within 5 minutes), reducing simulated false positives through timeframe and user correlation.
Configured Suricata for passive traffic capture on host-only network, enabling application-layer visibility (e.g., HTTP/DNS alerts).
Maintained cost-free setup using free tools; ensured isolation with no bridged networking to mimic secure lab environments.

Skills Demonstrated:
SIEM Configuration & Log Analysis (Wazuh)
Intrusion Detection Systems (Suricata IDS)
VPN Setup & Monitoring (OpenVPN)
Custom Rule Writing & Alert Correlation
Network Protocol Analysis & Anomaly Detection
Linux Administration (Ubuntu Server)

Tools & Technologies: Wazuh SIEM, Suricata 7.0.3, OpenVPN, VirtualBox (host-only network: 192.168.56.0/24), Nano for editing.
Relevance to SOC Roles: This project mirrors Tier 1 tasks like alert monitoring, basic investigation, and escalation preparation. It builds on my existing Wazuh homelab (15,000+ daily events, 75+ simulated attacks, MTTD <40s) by adding network-layer defense.

Architecture Overview

Environment: Isolated VirtualBox setup with Ubuntu Server (Wazuh Manager + Suricata + OpenVPN Server), Windows 11 Endpoint (monitored via Wazuh agent), Kali Linux (for safe simulations).
Network: Host-only adapter (192.168.56.0/24) with promiscuous mode enabled for Suricata traffic capture.
Log Flow: Suricata EVE JSON → Wazuh (json format); OpenVPN logs → Wazuh (syslog format); Windows events (e.g., 4625 failed logins) via agent.
Detection Logic: Custom rules correlate events (e.g., OpenVPN connect + Windows local login) for high-confidence alerts.

text[ Kali (Simulator) ] --- (Simulated Attacks/Scans/VPN Connect) ---> [ Windows 11 Endpoint ]
                                                              |
                                                              v
[ Ubuntu Server: Wazuh SIEM + Suricata IDS + OpenVPN Server ] <--- Logs Ingested & Rules Applied
Setup Steps & Screenshots
Below is a step-by-step walkthrough of the implementation, with corresponding screenshots for proof. All commands were executed on Ubuntu Server.

Install Suricata on Ubuntu
Command: sudo apt install suricata jq -yInstall Suricata on Ubuntu
Download Suricata Update
Command: sudo suricata-updateDownload Suricata Update
Going to Config Suricata
Command: sudo nano /etc/suricata/suricata.yamlGoing to Config Suricata
Change of Packet Interface for Capture Traffic
Updated af-packet interface to enp0s8 for traffic monitoring.Change of Packet Interface for Capture Traffic
Going to Change Current Home Net Address
Set HOME_NET to "[192.168.56.0/24]" for lab-specific monitoring.Going to Change Current Home Net Address
Enable Eve Logs
Enabled EVE JSON output for detailed alerts (http, dns, etc.).Enable Eve Logs
Start Suricata
Command: sudo systemctl start suricataStart Suricata
Suricata Running Successfully
Command: sudo systemctl status suricataSuricata Running Successfully
Install OpenVPN
Command: sudo apt install openvpn easy-rsa -yInstall OpenVPN
Create Easy RSA Directory
Command: make-cadir ~/openvpn-caCreate Easy RSA Directory
Edit Vars and Set Lab Details
Configured vars with SHA256 digest and lab-specific details (e.g., KEY_COUNTRY="LK").Edit Vars and Set Lab Details
Creating Certificate
Generated CA, server/client certs, DH params (2048-bit), and ta.key.Creating Certificate
Config Server
Edited /etc/openvpn/server/server.conf to push routes (192.168.56.0/24).Config Server
Check Status OpenVPN
Command: sudo systemctl status openvpn-server@serverCheck Status OpenVPN
Add Suricata and OpenVPN Log to Wazuh
Edited /var/ossec/etc/ossec.conf to ingest eve.json (JSON) and openvpn.log (syslog).Add Suricata and OpenVPN Log to Wazuh
Restarted Wazuh
Command: /var/ossec/bin/wazuh-control restartRestarted Wazuh
VPN Correlation Rules
Added custom group "vpn_local" with rules for VPN connect detection.VPN Correlation Rules
Example Rule for Local Login in 5 Min
Rule for correlating multiple events (timeframe 300s, same_user yes).Example Rule for Local Login in 5 Min

Testing & Validation

Simulated VPN connections from Kali and local logins on Windows to trigger rules.
Verified logs in Wazuh dashboard: Suricata alerts on network flows; OpenVPN auth events correlated for anomalies.
Potential Improvements: Add GeoIP module for distance-based impossible travel; tune rules for lower false positives.

Learnings & Resume Impact
This project reinforced my skills in SIEM operations, IDS configuration, and anomaly detection—directly applicable to Tier 1 SOC tasks like alert triage and log analysis. It extends my ongoing Wazuh homelab by adding network visibility, showcasing my ability to integrate tools for comprehensive monitoring.
For recruiters: This demonstrates proactive learning, problem-solving, and practical application of cybersecurity concepts in a cost-effective, isolated environment.
Future Enhancements

Integrate Sysmon for advanced endpoint process logging.
Add TheHive for automated incident response.
Map detections to MITRE ATT&CK framework.
Deploy in AWS for cloud-based scalability.
