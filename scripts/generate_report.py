"""
generate_report.py – Generuje kombinovaný update report (MITRE + XSOAR)
Čte: data/mitre_changes.json + data/xsoar_changes.json
Výstup: reports/update_YYYY-MM.md + data/github_issue.json
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from config import WATCHED_PACKS

NOW = datetime.now(timezone.utc)
REPORT_DATE = NOW.strftime("%Y-%m")
REPORT_FILE = f"reports/update_{REPORT_DATE}.md"
ISSUE_FILE  = "data/github_issue.json"


def load_json(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def severity_icon(pack_name: str) -> str:
    """Ikona závažnosti pro speciální případy."""
    if pack_name == "Microsoft365Defender":
        return "🔴"
    return "🟡"


def build_report(mitre: dict, xsoar: dict) -> str:
    lines = []
    today = NOW.strftime("%d. %m. %Y")
    has_content = bool(mitre.get("new_techniques") or xsoar)

    lines += [
        f"# Monthly Update Report – {REPORT_DATE}",
        f"",
        f"**Datum kontroly:** {today}  ",
        f"**ATT&CK verze:** {mitre.get('old_version', '–')} → {mitre.get('new_version', '–')}  ",
        f"**XSOAR pack změny:** {len(xsoar)}  ",
        f"",
    ]

    if not has_content and not mitre.get("first_run"):
        lines += [
            "## ✅ Žádné změny",
            "",
            "Tento týden nebyly detekovány žádné relevantní aktualizace.",
            "",
            "---",
            "_Generováno automaticky: soc-playbook-library/scripts/generate_report.py_",
        ]
        return "\n".join(lines)

    # ── XSOAR sekce ──────────────────────────────────────────────────────────
    if xsoar:
        lines += ["## XSOAR Pack Updates", ""]

        # Kritické (Microsoft365Defender deprecace)
        critical = {k: v for k, v in xsoar.items() if k == "Microsoft365Defender"}
        normal   = {k: v for k, v in xsoar.items() if k != "Microsoft365Defender"}

        if critical:
            lines += ["### 🔴 Kritické – vyžaduje akci", ""]
            for pack, info in critical.items():
                lines += [
                    f"#### {pack}  `{info['old']} → {info['new']}`",
                    f"_{info['purpose']}_",
                    "",
                    "⚠️ **UPOZORNĚNÍ:** Deprecace Advanced Hunting API potvrzena – deadline **31. 1. 2027**",
                    "",
                    "**Požadovaná akce:** Migrovat na `MicrosoftGraphSecurity` ve všech playboocích:",
                    "- PB-04 Brute Force",
                    "- PB-05 Compromised Account",
                    "- PB-12 Geo-based Login",
                    "",
                ]

        if normal:
            lines += ["### 🟡 Doporučená aktualizace", ""]
            for pack, info in normal.items():
                lines += [
                    f"#### {pack}  `{info['old']} → {info['new']}`",
                    f"_{info['purpose']}_",
                    "",
                ]
                if info.get("changelog"):
                    lines += ["**Změny:**", ""]
                    for item in info["changelog"][:8]:
                        if item.startswith("**"):
                            lines.append(f"_{item}_")
                        else:
                            lines.append(item)
                    lines.append("")

                affected = []
                # Najdi dotčené playbooky podle pack name
                pack_playbook_map = {
                    "MicrosoftGraphUser": ["PB-04", "PB-05", "PB-12"],
                    "AzureLogAnalytics": ["PB-04", "PB-05", "PB-12"],
                    "MicrosoftDefenderAdvancedThreatProtection": ["PB-02", "PB-03", "PB-04"],
                    "CortexXDR": ["PB-02", "PB-03"],
                    "AbuseDB": ["PB-04", "PB-08", "PB-12"],
                    "MaxMind_GeoIP2": ["PB-04", "PB-08", "PB-12"],
                    "FortiGate": ["PB-06", "PB-08"],
                    "Jira": ["všechny PB"],
                    "ServiceNowv2": ["všechny PB"],
                    "MicrosoftTeams": ["všechny PB"],
                    "Slack": ["všechny PB"],
                }
                affected = pack_playbook_map.get(pack, [])
                if affected:
                    lines += [f"**Dotčené playbooky:** {', '.join(affected)}", ""]

    # ── MITRE sekce ──────────────────────────────────────────────────────────
    new_techniques = mitre.get("new_techniques", [])
    if new_techniques:
        lines += [
            "## MITRE ATT&CK – Nové techniky (relevantní pro stack)",
            "",
            "| Technika | Název | Platformy | Dotčené PB |",
            "|---|---|---|---|",
        ]
        for t in new_techniques:
            platforms = ", ".join(t.get("platforms", [])[:2])
            affected  = ", ".join(t.get("affected_playbooks", [])) or "–"
            lines.append(
                f"| `{t['id']}` | {t['name']} | {platforms} | {affected} |"
            )
        lines += [""]

        lines += [
            "### Doporučení",
            "",
        ]
        for t in new_techniques:
            affected = t.get("affected_playbooks", [])
            if affected:
                lines.append(
                    f"- **{t['id']} {t['name']}** → aktualizovat sekce 6, 15 v: "
                    f"{', '.join(affected)}"
                )
            else:
                lines.append(
                    f"- **{t['id']} {t['name']}** → zvážit nový playbook"
                )
        lines += [""]

    # ── Beze změny ────────────────────────────────────────────────────────────
    unchanged = [p for p in WATCHED_PACKS if p not in xsoar]
    if unchanged:
        lines += [
            "## ℹ️ Bez změn",
            "",
            ", ".join(f"`{p}`" for p in unchanged),
            "",
        ]

    lines += [
        "---",
        f"_Generováno automaticky {today} · soc-playbook-library/scripts/generate_report.py_",
    ]

    return "\n".join(lines)


def build_issue_body(mitre: dict, xsoar: dict) -> dict:
    """Vytvoří payload pro GitHub Issue."""
    total = len(xsoar) + len(mitre.get("new_techniques", []))
    if total == 0:
        return {}

    title = f"🔄 Update Report {REPORT_DATE} – {total} položek k aktualizaci"

    body_lines = [
        f"## Automatický update report – {REPORT_DATE}",
        "",
        f"Detekováno **{len(xsoar)} XSOAR pack updates** a "
        f"**{len(mitre.get('new_techniques', []))} nových ATT&CK technik**.",
        "",
        f"📄 Plný report: [`reports/update_{REPORT_DATE}.md`]"
        f"(../blob/main/reports/update_{REPORT_DATE}.md)",
        "",
    ]

    if xsoar:
        body_lines += ["### XSOAR k aktualizaci", ""]
        for pack, info in xsoar.items():
            icon = severity_icon(pack)
            body_lines.append(
                f"- {icon} `{pack}` {info['old']} → **{info['new']}**"
            )
        body_lines.append("")

    new_tech = mitre.get("new_techniques", [])
    if new_tech:
        body_lines += ["### Nové ATT&CK techniky", ""]
        for t in new_tech[:10]:
            affected = ", ".join(t.get("affected_playbooks", [])) or "–"
            body_lines.append(f"- `{t['id']}` {t['name']} → {affected}")
        body_lines.append("")

    body_lines += [
        "---",
        "_Vytvořeno automaticky GitHub Actions · weekly-update-check_",
    ]

    return {
        "title": title,
        "body": "\n".join(body_lines),
        "labels": ["update", "maintenance"],
    }


def update_reports_index(has_changes: bool, xsoar_count: int, mitre_count: int):
    """Aktualizuje reports/index.json – seznam všech reportů pro portál."""
    index_file = "reports/index.json"
    index = {"reports": [], "last_check": NOW.date().isoformat()}

    # Načti existující index
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            index = json.load(f)

    # Přidej aktuální report (jen pokud ještě není)
    report_entry = {
        "file": f"update_{REPORT_DATE}.md",
        "date": NOW.date().isoformat(),
        "has_changes": has_changes,
        "xsoar_count": xsoar_count,
        "mitre_count": mitre_count,
    }
    existing_files = [r["file"] for r in index.get("reports", [])]
    if report_entry["file"] not in existing_files:
        index.setdefault("reports", []).insert(0, report_entry)

    index["last_check"] = NOW.date().isoformat()

    with open(index_file, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    print(f"✅ reports/index.json aktualizován ({len(index['reports'])} reportů)")


def run():
    mitre = load_json("data/mitre_changes.json")
    xsoar  = load_json("data/xsoar_changes.json")

    os.makedirs("reports", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    report = build_report(mitre, xsoar)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"✅ Report uložen: {REPORT_FILE}")

    has_changes = bool(xsoar or mitre.get("new_techniques"))
    update_reports_index(
        has_changes=has_changes,
        xsoar_count=len(xsoar),
        mitre_count=len(mitre.get("new_techniques", [])),
    )

    issue = build_issue_body(mitre, xsoar)
    with open(ISSUE_FILE, "w", encoding="utf-8") as f:
        json.dump(issue, f, indent=2, ensure_ascii=False)

    if issue:
        print(f"✅ GitHub Issue payload: {ISSUE_FILE}")
    else:
        print("ℹ️  Žádné změny – GitHub Issue se nevytvoří.")


if __name__ == "__main__":
    run()
