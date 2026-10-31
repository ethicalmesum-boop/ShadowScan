🛡️ ShadowScan: Red Team Reconnaissance Framework

ShadowScan is a modular, multi-threaded reconnaissance framework designed for security researchers and Red Teamers to map the attack surface of a target organization efficiently.
🚀 Overview

ShadowScan automates the discovery of subdomains, DNS intelligence, and technology stack analysis. By wrapping powerful industry-standard tools, it provides a unified interface to gather actionable intelligence.
🛠️ Key Features

    Multi-Layered Discovery: Leverages Amass and DNSenum for deep subdomain enumeration.
    DNS Intelligence: Integration with dnsrecon and DNSmap for zone analysis and record mapping.
    Tech Stack Profiling: Automated identification of CMS, Web Servers, and Frameworks using WhatWeb.
    OSINT Harvesting: Email and domain-related intelligence gathering via theHarvester.
    Turbo Mode: Implemented via concurrent.futures for high-speed parallel execution.
    Professional UI: Clean, formatted output using the Rich library.

📦 Installation
Prerequisites

Ensure you have the following tools installed on your Kali Linux system:

    subfinder, httpx, dnsrecon, dnsmap, whatweb, theharvester

Setup
bash

# Clone the repository
git clone https://github.com/ethicalmesum-boop/ShadowScan.git
# Navigate to the directory
cd ShadowScan
# Install required Python libraries
pip3 install rich

🛠️ Usage

Run the framework using the main entry point:
bash

python3 main.py

Follow the on-screen prompts to enter your target domain (e.g., example.com).
📂 Project Structure

    main.py: The central orchestrator.
    modules/: Contains specialized logic for:
        recon.py: Subdomain discovery.
        dns.py: DNS records & zone transfers.
        tech.py: Technology fingerprinting.
        osint.py: Open-source intelligence gathering.
    reports/: Stores all generated JSON and TXT reports.

⚠️ Disclaimer

This tool is for educational and professional security testing only. Never run ShadowScan against a target you do not have explicit permission to test. The author is not responsible for any misuse of this tool
