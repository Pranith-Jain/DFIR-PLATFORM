threat_actors = [
    {
        "name": "Storm-1747",
        "aliases": "DEV-1747 · Sangria Tempest · Tycoon2FA",
        "status": "Active",
        "level": "Advanced",
        "desc": "Financially motivated threat actor that developed Tycoon2FA, one of the most prolific PhaaS platforms. Enabled tens of millions of phishing messages reaching 500,000+ organizations monthly. March 2026 law enforcement seized 330 domains but platform resumed within days.",
        "origin": "Unknown (likely Nigeria-based)",
        "techniques": ["Phishing", "Adversary-in-the-Middle (AiTM)", "Session Token Theft"],
        "tools": ["Tycoon2FA", "EvilProxy"],
        "color": "from-red-500 to-orange-500",
        "nation_state": False
    },
    {
        "name": "Rhysida",
        "aliases": "Rhysida Ransomware · Vice Society · OysterLoader",
        "status": "Active",
        "level": "Intermediate",
        "desc": "Highly active RaaS operation emerged May 2023, linked to Vice Society. 265+ victims documented. Uses multi-tiered infrastructure, typosquatting, SEO poisoning. Recent evolution includes abuse of Microsoft Trusted Signing certificates (200+ revoked) and cloud-native exfiltration via Azure tools.",
        "origin": "Unknown (likely Eastern Europe)",
        "techniques": ["Ransomware-as-a-Service", "Data Extortion", "Living off the Land"],
        "tools": ["Rhysida Ransomware", "OysterLoader", "Azure Copy"],
        "color": "from-purple-500 to-fuchsia-500",
        "nation_state": False
    },
    {
        "name": "BianLian",
        "aliases": "BianLian Group · Bitter Scorpius",
        "status": "Active",
        "level": "Advanced",
        "desc": "Russia-based ransomware developer and data extortion group. Active since June 2022, shifted to exfiltration-based extortion in 2023. Targets healthcare, manufacturing, professional services. Uses pressure tactics including printing ransom notes to network printers.",
        "origin": "Unknown (Eastern Europe/Russia)",
        "techniques": ["Data Extortion", "ProxyShell Exploitation", "Advanced Persistence"],
        "tools": ["BianLian Go Backdoor", "PowerShell"],
        "color": "from-blue-500 to-cyan-500",
        "nation_state": False
    },
    {
        "name": "Lazarus Group",
        "aliases": "Hidden Cobra · ZINC · Diamond Sleet",
        "status": "Active",
        "level": "Nation-State",
        "desc": "Significantly evolved in 2025-2026: shifted to RaaS using Medusa, executed largest crypto heist ($1.5B Bybit). AI-generated content for social engineering. 230+ malicious npm/PyPI packages. Subgroup Stonefly targets healthcare with ransomware.",
        "origin": "North Korea",
        "techniques": ["Cryptocurrency Theft", "Supply Chain Attack", "Social Engineering"],
        "tools": ["AppleJeus", "Dtrack", "Medusa Ransomware"],
        "color": "from-cyan-500 to-blue-500",
        "nation_state": True
    },
    {
        "name": "Volt Typhoon",
        "aliases": "VANGUARD PANDA · Bronze Silhouette",
        "status": "Active",
        "level": "Nation-State",
        "desc": "Chinese state-sponsored actor focused on pre-positioning for disruptive operations against U.S. critical infrastructure. Active since mid-2021. Exclusively uses LOTL techniques, avoiding custom malware. Compromised SOHO routers as operational relay boxes.",
        "origin": "China",
        "techniques": ["Living off the Land", "Credential Access", "Network Infrastructure Compromise"],
        "tools": ["Living off the Land Tools", "SOHO Router Botnets"],
        "color": "from-yellow-600 to-orange-600",
        "nation_state": True
    },
    {
        "name": "APT28",
        "aliases": "Fancy Bear · Sofacy · Pawn Storm",
        "status": "Active",
        "level": "Nation-State",
        "desc": "GRU Unit 26165. Rapidly weaponizes 1-day vulnerabilities (CVE-2026-21509 within 24 hours). Deploys AI-powered malware. Heavily modified Covenant framework. Major campaigns: Operation MacroMaze, Operation Neusploit. Targets Western logistics supporting Ukraine.",
        "origin": "Russia",
        "techniques": ["Exploitation of Public-Facing Applications", "Spearphishing", "Credential Stuffing"],
        "tools": ["Covenant", "X-Agent", "Sednitro"],
        "color": "from-violet-500 to-purple-500",
        "nation_state": True
    }
]
