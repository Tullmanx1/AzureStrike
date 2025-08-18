# AzureStrike
AzureStrike is an HTA-based application designed to simulate Azure (Entra) scenarios for Red Team simulations and adversarial training. The goal of this project is to provide a lightweight and interactive way to practice offensive techniques against Azure environments in a controlled lab setup.

# Building the Scenarios
<img width="1907" height="909" alt="image" src="https://github.com/user-attachments/assets/c6e5cabc-fbc0-4d4b-a59e-e200476420ae" />

The HTA application provides simple **Run Scenarios** buttons that trigger PowerShell scripts placed in the same directory. Each script builds a unique scenario modeled after real-world attack methodologies and techniques that are commonly seen in Red Team engagements. Some of these are based on research and hands-on work replicating techniques from training courses, I've personally taken so understanding the Azure technologieswas important before I implemented them.
The tool leverages `Connect-AzAccount`, `Connect-MgGraph`, the Azure CLI, and the Azure Functions Core Tools to deploy vulnerable functions into Azure. Resource names are hardcoded so they remain consistent across runs, and if the required tools are not present, a PowerShell setup script is provided to install them beforehand.

# Current Scenarios
1. **Weak Credentials and Lateral Movement** – Simulates an initial access vector through weak credentials. The objective is to move laterally through the environment to locate the flag.  
2. **SSRF and Managed Identities** – Deploys an Azure-hosted webpage containing an SSRF vulnerability. Exploiting this requires leveraging managed identities to escalate and capture the flag.  
3. **Linux Web Vulnerability and Database Discovery** – Hosts a vulnerable web service on a Linux VM. This scenario requires using Linux exploitation skills to extract credentials, pivot, and identify a database that stores the flag.

# The Script
Currently it needs a helper scripted to be installed beforehand so the installtion and setup runs successfully this is named `Setup.ps1` it relies on winget to install packages and keep tool up to date. When a scenario has been successfully installed you will receive your `Initial Access`.
<p align="center"><img width="534" height="354" alt="image" src="https://github.com/user-attachments/assets/213c7138-532f-470a-92fe-154c1b3326db" /></p>

# Roadmap
- Expand with additional scenarios to cover more Azure attack paths  
- Improve script or move to something other than an HTA

If you run into issues, please open an issue on this repository.
