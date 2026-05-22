"""
config.py – Konfigurace sledovaných XSOAR packů a stack mappingu
Repo: github.com/pgjmh7q5wj-rgb/soc-playbook-library
"""

# ── XSOAR Packs ke sledování ──────────────────────────────────────────────────
# Klíč = přesný název složky v demisto/content/Packs/
# Hodnota = popis účelu v našem stacku

WATCHED_PACKS = {
    # Identity / Entra ID
    "MicrosoftGraphUser":                       "Entra ID – disable, revoke, get user",
    "AzureLogAnalytics":                        "KQL queries – Sentinel / Log Analytics",

    # Defender / Advanced Hunting
    "Microsoft365Defender":                     "Advanced Hunting – DEPRECACE 31.1.2027",
    "MicrosoftDefenderAdvancedThreatProtection": "EDR isolation, ATP akce",
    "MicrosoftGraphSecurity":                   "Náhrada M365Defender po deprecaci",

    # Enrichment
    "MaxMind_GeoIP2":                           "IP geolocation",
    "AbuseDB":                                  "IP reputation (AbuseIPDB)",
    "VirusTotal":                               "File / IP / URL reputation",

    # Firewall
    "FortiGate":                                "Block IP, address groups",

    # EDR / XDR
    "CortexXDR":                                "XDR isolation, query",
    "CrowdStrikeFalcon":                        "Falcon contain host",
    "SentinelOne":                              "Isolate machine",

    # Ticketing
    "Jira":                                     "Create incident ticket",
    "ServiceNowv2":                             "Create SNOW record",

    # Notifications
    "MicrosoftTeams":                           "Alert notifications",
    "Slack":                                    "Channel notifications",
}

# ── ATT&CK Stack Mapping ──────────────────────────────────────────────────────
# Filtry pro MITRE diff – techniky relevantní pro náš technologický stack

STACK_PLATFORMS = [
    "Windows",
    "Azure AD",
    "Office 365",
    "SaaS",
    "IaaS",
]

STACK_DATA_SOURCES = [
    "Logon Session",
    "User Account",
    "Process",
    "File",
    "Network Traffic",
    "Windows Registry",
    "Active Directory",
    "Application Log",
    "Cloud Service",
    "Email",
    "Web Proxy",
]

# ── Playbook → MITRE Mapping ──────────────────────────────────────────────────
# Které playbooky pokrývají které techniky (z manifest.json)
# Používá se pro "dotčené playbooky" v update reportu

PLAYBOOK_MITRE_MAP = {
    "PB-01": ["T1566", "T1598", "T1204"],
    "PB-02": ["T1059", "T1055", "T1036", "T1070"],
    "PB-03": ["T1486", "T1490", "T1489", "T1083"],
    "PB-04": ["T1110", "T1078", "T1021"],
    "PB-05": ["T1078", "T1098", "T1550"],
    "PB-06": ["T1048", "T1041", "T1567", "T1030"],
    "PB-08": ["T1071", "T1095", "T1572", "T1090", "T1102"],
    "PB-09": ["T1566", "T1585", "T1534", "T1036"],
    "PB-10": ["T1078", "T1496", "T1530", "T1537"],
    "PB-12": ["T1078", "T1134", "T1110"],
}

# ── GitHub API ────────────────────────────────────────────────────────────────
DEMISTO_CONTENT_REPO  = "demisto/content"
MITRE_CTI_REPO        = "mitre/cti"
MITRE_CTI_PATH        = "enterprise-attack/enterprise-attack.json"

# ── Cesty v repozitáři ────────────────────────────────────────────────────────
DATA_DIR              = "data"
REPORTS_DIR           = "reports"
ATTACK_VERSION_FILE   = "data/attack_version.json"
XSOAR_VERSIONS_FILE   = "data/xsoar_pack_versions.json"
