"""
TuxBrowser - Storage Manager
Handles persistent storage for bookmarks, history, settings, and shield statistics.
Uses atomic JSON writes and thread-safe file handling.
"""

import json
import os
import shutil
import time
import threading
from typing import Any, Dict, List, Optional


class TuxStorage:
    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None:
            config_home = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
            self.data_dir = os.path.join(config_home, "tux-browser")
        else:
            self.data_dir = data_dir

        os.makedirs(self.data_dir, exist_ok=True)
        self.bookmarks_file = os.path.join(self.data_dir, "bookmarks.json")
        self.history_file = os.path.join(self.data_dir, "history.json")
        self.settings_file = os.path.join(self.data_dir, "settings.json")
        self.stats_file = os.path.join(self.data_dir, "shield_stats.json")
        self._lock = threading.Lock()

        self._init_defaults()

    def _atomic_write_json(self, file_path: str, data: Any) -> None:
        """Atomic write using a temporary file to avoid corruption on unexpected shutdown."""
        with self._lock:
            tmp_path = f"{file_path}.tmp.{os.getpid()}.{time.time_ns()}"
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                shutil.move(tmp_path, file_path)
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                print(f"[TuxStorage] Error saving {file_path}: {e}")

    def _read_json(self, file_path: str, default: Any) -> Any:
        with self._lock:
            if not os.path.exists(file_path):
                return default
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[TuxStorage] Error reading {file_path}: {e}")
                return default

    def _init_defaults(self) -> None:
        default_settings = {
            "search_engine": "TuxFind",
            "search_engines": {
                "TuxFind": "tux://search?q={query}",
                "DuckDuckGo": "https://duckduckgo.com/?q={query}",
                "Brave": "https://search.brave.com/search?q={query}",
                "SearXNG": "https://searx.be/search?q={query}",
                "Startpage": "https://www.startpage.com/sp/search?query={query}"
            },
            "home_page": "tux://home",
            "block_trackers": True,
            "block_ads": True,
            "https_only": True,
            "block_third_party_cookies": True,
            "javascript_enabled": True,
            "do_not_track": True,
            "webrtc_leak_protection": True,
            "block_ipv6_leaks": True,
            "anti_fingerprinting": True,
            "strip_tracking_urls": True,
            "spoof_timezone": True,
            "kill_switch_enabled": True,
            "security_level": "standard",
            "clear_history_on_exit": False,
            "clear_cache_on_exit": False,
            "show_bookmarks_bar": True,
            "custom_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "dark_theme": True,
            "zoom_level": 100
        }

        default_bookmarks = [
            {"id": "1", "title": "🐧 Tux Home", "url": "tux://home", "date": time.time(), "category": "General"},
            {"id": "2", "title": "🔍 TuxFind Search", "url": "tux://home", "date": time.time(), "category": "Search"},
            {"id": "3", "title": "🛡️ Security Shield", "url": "tux://shield", "date": time.time(), "category": "Security"},
            {"id": "4", "title": "🐧 Kernel.org", "url": "https://www.kernel.org", "date": time.time(), "category": "Linux"},
            {"id": "5", "title": "📖 ArchWiki", "url": "https://wiki.archlinux.org", "date": time.time(), "category": "Linux"},
            {"id": "6", "title": "🔐 EFF Privacy", "url": "https://www.eff.org", "date": time.time(), "category": "Privacy"},
            {"id": "7", "title": "🛡️ Privacy Guides", "url": "https://www.privacyguides.org", "date": time.time(), "category": "Privacy"}
        ]

        default_stats = {
            "total_trackers_blocked": 0,
            "total_ads_blocked": 0,
            "total_https_upgrades": 0,
            "domains_whitelist": [],
            "custom_blocklist": []
        }

        if not os.path.exists(self.settings_file):
            self._atomic_write_json(self.settings_file, default_settings)
        else:
            # Upgrade existing settings if needed
            existing = self._read_json(self.settings_file, {})
            if "Firefox" in existing.get("custom_user_agent", ""):
                existing["custom_user_agent"] = default_settings["custom_user_agent"]
                self._atomic_write_json(self.settings_file, existing)
        if not os.path.exists(self.bookmarks_file):
            self._atomic_write_json(self.bookmarks_file, default_bookmarks)
        if not os.path.exists(self.history_file):
            self._atomic_write_json(self.history_file, [])
        if not os.path.exists(self.stats_file):
            self._atomic_write_json(self.stats_file, default_stats)

    # ----------------- Settings -----------------
    def get_settings(self) -> Dict[str, Any]:
        return self._read_json(self.settings_file, {})

    def get_setting(self, key: str, default: Any = None) -> Any:
        settings = self.get_settings()
        return settings.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        settings = self.get_settings()
        settings[key] = value
        self._atomic_write_json(self.settings_file, settings)

    def update_settings(self, updates: Dict[str, Any]) -> None:
        settings = self.get_settings()
        settings.update(updates)
        self._atomic_write_json(self.settings_file, settings)

    # ----------------- Bookmarks -----------------
    def get_bookmarks(self) -> List[Dict[str, Any]]:
        return self._read_json(self.bookmarks_file, [])

    def add_bookmark(self, title: str, url: str, category: str = "General") -> bool:
        if not url or url.startswith("tux://history") or url.startswith("tux://settings"):
            return False
        bookmarks = self.get_bookmarks()
        # Avoid duplicate URLs
        for b in bookmarks:
            if b.get("url") == url:
                b["title"] = title
                self._atomic_write_json(self.bookmarks_file, bookmarks)
                return True
        new_item = {
            "id": str(int(time.time() * 1000)),
            "title": title or url,
            "url": url,
            "date": time.time(),
            "category": category
        }
        bookmarks.insert(0, new_item)
        self._atomic_write_json(self.bookmarks_file, bookmarks)
        return True

    def remove_bookmark(self, url: str) -> bool:
        bookmarks = self.get_bookmarks()
        initial_len = len(bookmarks)
        bookmarks = [b for b in bookmarks if b.get("url") != url]
        if len(bookmarks) != initial_len:
            self._atomic_write_json(self.bookmarks_file, bookmarks)
            return True
        return False

    def is_bookmarked(self, url: str) -> bool:
        bookmarks = self.get_bookmarks()
        return any(b.get("url") == url for b in bookmarks)

    # ----------------- History -----------------
    def get_history(self, limit: int = 500) -> List[Dict[str, Any]]:
        history = self._read_json(self.history_file, [])
        return history[:limit]

    def add_history(self, title: str, url: str) -> None:
        if not url or url.startswith("tux://"):
            return
        history = self._read_json(self.history_file, [])
        # Check if same URL was visited recently (update timestamp)
        existing = next((h for h in history if h.get("url") == url), None)
        if existing:
            existing["title"] = title or existing.get("title", url)
            existing["timestamp"] = time.time()
            existing["visit_count"] = existing.get("visit_count", 1) + 1
            # Move to front
            history.remove(existing)
            history.insert(0, existing)
        else:
            history.insert(0, {
                "url": url,
                "title": title or url,
                "timestamp": time.time(),
                "visit_count": 1
            })
        # Keep maximum 2000 entries
        history = history[:2000]
        self._atomic_write_json(self.history_file, history)

    def clear_history(self) -> None:
        self._atomic_write_json(self.history_file, [])

    def delete_history_item(self, url: str) -> None:
        history = self._read_json(self.history_file, [])
        history = [h for h in history if h.get("url") != url]
        self._atomic_write_json(self.history_file, history)

    # ----------------- Stats & Shield -----------------
    def get_shield_stats(self) -> Dict[str, Any]:
        return self._read_json(self.stats_file, {
            "total_trackers_blocked": 0,
            "total_ads_blocked": 0,
            "total_https_upgrades": 0,
            "domains_whitelist": [],
            "custom_blocklist": []
        })

    def increment_stat(self, key: str, count: int = 1) -> None:
        stats = self.get_shield_stats()
        stats[key] = stats.get(key, 0) + count
        self._atomic_write_json(self.stats_file, stats)

    def is_domain_whitelisted(self, domain: str) -> bool:
        stats = self.get_shield_stats()
        whitelist = stats.get("domains_whitelist", [])
        return domain.lower() in [d.lower() for d in whitelist]

    def toggle_domain_whitelist(self, domain: str) -> bool:
        stats = self.get_shield_stats()
        whitelist = stats.get("domains_whitelist", [])
        domain_lower = domain.lower()
        if domain_lower in [d.lower() for d in whitelist]:
            whitelist = [d for d in whitelist if d.lower() != domain_lower]
            active = False
        else:
            whitelist.append(domain_lower)
            active = True
        stats["domains_whitelist"] = whitelist
        self._atomic_write_json(self.stats_file, stats)
        return active

    # ----------------- Unified Profile Export / Import (1 JSON) -----------------
    def export_profile_dict(self) -> Dict[str, Any]:
        """Returns all configuration, bookmarks, history, and stats in 1 consolidated JSON dictionary."""
        return {
            "app": "FishTux",
            "format_version": 2,
            "exported_at": time.time(),
            "settings": self.get_settings(),
            "bookmarks": self.get_bookmarks(),
            "history": self.get_history(),
            "shield_stats": self.get_shield_stats()
        }

    def import_profile_dict(self, data: Dict[str, Any]) -> bool:
        """Imports and applies all settings, bookmarks, history, and stats from 1 JSON dictionary."""
        if not isinstance(data, dict):
            return False
        try:
            if "settings" in data and isinstance(data["settings"], dict):
                self._atomic_write_json(self.settings_file, data["settings"])
            if "bookmarks" in data and isinstance(data["bookmarks"], list):
                self._atomic_write_json(self.bookmarks_file, data["bookmarks"])
            if "history" in data and isinstance(data["history"], list):
                self._atomic_write_json(self.history_file, data["history"])
            if "shield_stats" in data and isinstance(data["shield_stats"], dict):
                self._atomic_write_json(self.stats_file, data["shield_stats"])
            return True
        except Exception as e:
            print(f"[TuxStorage] Error importing profile: {e}")
            return False

    def reset_to_defaults(self) -> None:
        """Resets all settings, bookmarks, and shield stats to default."""
        for f in (self.settings_file, self.bookmarks_file, self.history_file, self.stats_file):
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass
        self._init_defaults()

