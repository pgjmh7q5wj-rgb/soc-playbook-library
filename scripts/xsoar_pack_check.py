"""
xsoar_pack_check.py – Kontrola verzí XSOAR packů přes GitHub API
Zdroj: github.com/demisto/content (= synchronizováno s XSOAR Marketplace)

Výstup: data/xsoar_pack_versions.json (aktualizovaný)
        dict changes = {pack_name: {old, new, changelog_items}}
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Přidej scripts/ do path pro import config
sys.path.insert(0, os.path.dirname(__file__))
from config import WATCHED_PACKS, DEMISTO_CONTENT_REPO, XSOAR_VERSIONS_FILE

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def gh_get(path: str) -> dict | list:
    """GitHub API GET s volitelnou autentizací."""
    url = f"{GITHUB_API}/{path.lstrip('/')}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "soc-playbook-update-checker")
    if GITHUB_TOKEN:
        req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  ⚠️  GitHub API {url} → HTTP {e.code}")
        return {}
    except Exception as e:
        print(f"  ⚠️  GitHub API error: {e}")
        return {}


def get_pack_version(pack_name: str) -> dict:
    """Načte pack_metadata.json z demisto/content."""
    path = f"repos/{DEMISTO_CONTENT_REPO}/contents/Packs/{pack_name}/pack_metadata.json"
    data = gh_get(path)
    if not data or "content" not in data:
        return {}
    import base64
    try:
        content = base64.b64decode(data["content"]).decode()
        return json.loads(content)
    except Exception:
        return {}


def get_pack_changelog(pack_name: str, since_version: str) -> list[str]:
    """Načte CHANGELOG.md a vrátí položky novější než since_version."""
    path = f"repos/{DEMISTO_CONTENT_REPO}/contents/Packs/{pack_name}/CHANGELOG.md"
    data = gh_get(path)
    if not data or "content" not in data:
        return []
    import base64
    try:
        changelog = base64.b64decode(data["content"]).decode()
    except Exception:
        return []

    items = []
    in_new_section = False
    for line in changelog.splitlines():
        # Nová verze sekce začíná ## x.x.x
        if line.startswith("## "):
            ver = line.strip("# \n")
            # Pokud narazíme na since_version nebo starší, stop
            if ver == since_version:
                break
            in_new_section = True
            items.append(f"**{ver}**")
        elif in_new_section and line.strip().startswith("-"):
            items.append(line.strip())

    return items[:20]  # Max 20 položek


def load_saved_versions() -> dict:
    """Načte uložené verze z data/xsoar_pack_versions.json."""
    if os.path.exists(XSOAR_VERSIONS_FILE):
        with open(XSOAR_VERSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_versions(versions: dict):
    """Uloží aktuální verze do data/xsoar_pack_versions.json."""
    os.makedirs(os.path.dirname(XSOAR_VERSIONS_FILE), exist_ok=True)
    with open(XSOAR_VERSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(versions, f, indent=2, ensure_ascii=False)


def check_packs() -> dict:
    """
    Projde všechny WATCHED_PACKS, porovná verze.
    Vrátí dict změn: {pack_name: {old, new, description, changelog}}
    """
    saved = load_saved_versions()
    current = {}
    changes = {}

    print(f"🔍 Kontroluji {len(WATCHED_PACKS)} XSOAR packů...")

    for pack_name, purpose in WATCHED_PACKS.items():
        print(f"  → {pack_name}...", end=" ", flush=True)
        metadata = get_pack_version(pack_name)

        if not metadata:
            print("nenalezen")
            continue

        new_version = metadata.get("currentVersion", "unknown")
        current[pack_name] = {
            "version": new_version,
            "description": metadata.get("description", purpose),
            "updated": datetime.now(timezone.utc).isoformat(),
            "purpose": purpose,
        }

        old_version = saved.get(pack_name, {}).get("version", "")

        if not old_version:
            print(f"nový záznam → {new_version}")
        elif old_version != new_version:
            print(f"UPDATE {old_version} → {new_version} ✅")
            changelog = get_pack_changelog(pack_name, old_version)
            changes[pack_name] = {
                "old": old_version,
                "new": new_version,
                "purpose": purpose,
                "changelog": changelog,
            }
        else:
            print(f"beze změny ({new_version})")

    # Ulož aktuální verze
    save_versions(current)
    return changes


if __name__ == "__main__":
    changes = check_packs()
    if changes:
        print(f"\n✅ Nalezeno {len(changes)} updated packů:")
        for name, info in changes.items():
            print(f"  • {name}: {info['old']} → {info['new']}")
    else:
        print("\n✅ Žádné změny XSOAR packů.")

    # Předej výsledek jako JSON soubor pro generate_report.py
    os.makedirs("data", exist_ok=True)
    with open("data/xsoar_changes.json", "w") as f:
        json.dump(changes, f, indent=2, ensure_ascii=False)
