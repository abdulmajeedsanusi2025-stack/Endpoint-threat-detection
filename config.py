"""
Configuration settings for AI-Powered Endpoint Threat Detection System.
Operates completely offline with zero external network dependencies.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_PATH = DATA_DIR / "threat_model.joblib"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Telemetry Configuration
TELEMETRY_CONFIG = {
    # Time window for file modification rate tracking (seconds)
    "file_window_seconds": 60,
    # Process scan interval (seconds)
    "scan_interval": 2.0,
    # Number of top processes by resource consumption / risk to track actively
    "max_active_processes": 80,
    # Monitored directory for file modification tracking (defaults to local workspace sandbox)
    "watch_directories": [
        str(BASE_DIR / "sandbox_monitored"),
    ]
}

# Suspicious Threat Indicators (Offline Knowledge Base)
THREAT_INDICATORS = {
    # Suspicious network ports commonly used by C2, reverse shells, trojans, cryptominers
    "suspicious_ports": {
        4444,   # Metasploit Default Listener
        1337,   # Elite / Hacker convention port
        6667,   # IRC C2 botnet communication
        3333,   # Stratum mining protocol (XMRig, etc.)
        4445,   # Secondary Metasploit port
        5555,   # Freeciv / Android ADB trojan
        8888,   # Common C2 HTTP proxy
        9999,   # Common backdoor listener
        31337,  # Back Orifice / SubSeven legacy backdoor
        7777,   # Common RAT listener
        2222,   # Non-standard SSH tunnel
        14444,  # Monero pool mining
    },

    # Suspicious process names or patterns (LOLBins, hacking tools, coin miners, wipers)
    "suspicious_processes": {
        "xmrig.exe", "xmrig", "minerd.exe", "ethminer.exe",
        "mimikatz.exe", "mimikatz", "pwdump.exe", "procdump.exe",
        "nc.exe", "netcat.exe", "ncat.exe", "socat.exe",
        "vssadmin.exe", "wbadmin.exe", "bcdedit.exe",
        "psexec.exe", "psexec",
        "certutil.exe", "bitsadmin.exe",
        "svch0st.exe", "scvhost.exe", "csrsss.exe", "lsasss.exe"  # Masquerading names
    },

    # Script hosts and shells that require scrutiny when exhibiting high network/file churn
    "script_hosts": {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", 
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    },

    # Known trusted system processes
    "trusted_system_processes": {
        "system", "system idle process", "registry", "smss.exe",
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "svchost.exe", "fontdrvhost.exe", "winlogon.exe",
        "dwm.exe", "explorer.exe", "spoolsv.exe"
    }
}

# Risk Engine Assessment Tiers
RISK_TIERS = ["Low", "Medium", "High", "Critical"]

# Quantitative Weights for Composite Risk Score (0 - 100%)
# Composite Score = sum(P(Tier) * Weight(Tier))
RISK_WEIGHTS = {
    "Low": 5.0,        # Benign background baseline
    "Medium": 35.0,    # Anomaly / elevated suspicion
    "High": 75.0,      # High probability malicious behavior
    "Critical": 100.0  # Active threat / destructive activity
}

# Thresholds for heuristic safety and rules calibration
THRESHOLDS = {
    "high_cpu_percent": 75.0,
    "high_memory_percent": 50.0,
    "ransomware_file_mod_threshold": 25,  # 25+ modifications within 60s
    "extreme_file_mod_threshold": 60,
    "young_process_age_seconds": 60,      # Process started less than 60s ago
    "infant_process_age_seconds": 15       # Process started less than 15s ago
}
