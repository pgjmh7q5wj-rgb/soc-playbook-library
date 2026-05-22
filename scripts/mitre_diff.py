"""
mitre_diff.py – MITRE ATT&CK diff
Zdroj: github.com/mitre/cti (enterprise-attack.json)

Porovná uloženou verzi s aktuální, filtruje podle stacku.
Výstup: data/mitre_changes.json
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    STACK_PLATFORMS, STACK_DATA_SOURCES, PLAYBOOK_MITRE_MAP,
    ATTACK_VERSION_FILE, MITRE_CTI_REPO, MITRE_CTI_PATH
)

ATTACK_URL = f"https://raw.githubusercontent.com/{MITRE_CTI_REPO}/master/{MITRE_CTI_PATH}"


def fetch_attack_json() -> dict:
    """Stáhne aktuální enterprise-attack.json z MITRE CTI repo."""
    print("📥 Stahuji ATT&CK enterprise-attack.json...", flush=True)
    try:
        req = urllib.request.Request(ATTACK_URL)
        req.add_header("User-Agent", "soc-playbook-update-checker")
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  ⚠️  Chyba při stahování ATT&CK: {e}")
        return {}


def load_saved_version() -> dict:
    """Načte uloženou verzi ATT&CK."""
    if os.path.exists(ATTACK_VERSION_FILE):
        with open(ATTACK_VERSION_FILE, "r") as f:
            return json.load(f)
    return {"version": "", "date": "", "technique_ids": []}


def save_version(version: str, technique_ids: list):
    """Uloží aktuální verzi."""
    os.makedirs("data", exist_ok=True)
    with open(ATTACK_VERSION_FILE, "w") as f:
        json.dump({
            "version": version,
            "date": datetime.now(timezone.utc).date().isoformat(),
            "technique_count": len(technique_ids),
            "technique_ids": technique_ids,
        }, f, indent=2)


def is_relevant(obj: dict) -> bool:
    """Vrátí True pokud technika je relevantní pro náš stack."""
    platforms = obj.get("x_mitre_platforms", [])
    data_sources = " ".join(obj.get("x_mitre_data_sources", []))

    platform_match = any(p in platforms for p in STACK_PLATFORMS)
    source_match = any(s.lower() in data_sources.lower() for s in STACK_DATA_SOURCES)

    return platform_match or source_match


def find_affected_playbooks(technique_id: str) -> list[str]:
    """Vrátí seznam playbooků dotčených danou technikou."""
    # Ořízni sub-techniku pro matching (T1078.004 → T1078)
    base_id = technique_id.split(".")[0]
    affected = []
    for pb_id, techniques in PLAYBOOK_MITRE_MAP.items():
        if technique_id in techniques or base_id in techniques:
            affected.append(pb_id)
    return affected


def parse_techniques(attack_data: dict) -> dict:
    """Extrahuje techniky z ATT&CK STIX bundle."""
    techniques = {}
    for obj in attack_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False):
            continue

        # Získej T-ID z external_references
        t_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                t_id = ref.get("external_id", "")
                break
        if not t_id:
            continue

        techniques[t_id] = {
            "id": t_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:300],
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "modified": obj.get("modified", ""),
            "relevant": is_relevant(obj),
        }
    return techniques


def get_attack_version(attack_data: dict) -> str:
    """Získá verzi ATT&CK z markings."""
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version", "unknown")
    # Fallback – hledej v identity
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "identity":
            return obj.get("x_mitre_version", "unknown")
    return "unknown"


def diff_techniques(old_ids: list, new_techniques: dict) -> dict:
    """Porovná staré a nové techniky, vrátí změny."""
    old_set = set(old_ids)
    new_set = set(new_techniques.keys())

    new_items = new_set - old_set
    removed = old_set - new_set

    changes = {
        "new": [],
        "removed": list(removed),
    }

    for t_id in sorted(new_items):
        tech = new_techniques.get(t_id, {})
        if tech.get("relevant"):
            changes["new"].append({
                "id": t_id,
                "name": tech["name"],
                "platforms": tech["platforms"],
                "data_sources": tech["data_sources"][:3],
                "affected_playbooks": find_affected_playbooks(t_id),
            })

    return changes


def run():
    attack_data = fetch_attack_json()
    if not attack_data:
        print("❌ Nepodařilo se stáhnout ATT&CK data.")
        sys.exit(1)

    new_version = get_attack_version(attack_data)
    new_techniques = parse_techniques(attack_data)
    saved = load_saved_version()
    old_version = saved.get("version", "")
    old_ids = saved.get("technique_ids", [])

    print(f"📊 ATT&CK verze: {old_version or 'první spuštění'} → {new_version}")
    print(f"   Technik celkem: {len(new_techniques)}, relevantní pro stack: "
          f"{sum(1 for t in new_techniques.values() if t['relevant'])}")

    changes = diff_techniques(old_ids, new_techniques)

    # Ulož aktuální stav
    save_version(new_version, list(new_techniques.keys()))

    # Výstup pro generate_report.py
    result = {
        "old_version": old_version,
        "new_version": new_version,
        "new_techniques": changes["new"],
        "removed_techniques": changes["removed"],
        "first_run": not bool(old_version),
    }

    with open("data/mitre_changes.json", "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    if changes["new"]:
        print(f"\n✅ {len(changes['new'])} nových relevantních technik.")
    else:
        print("\n✅ Žádné nové relevantní techniky.")

    return result


if __name__ == "__main__":
    run()
