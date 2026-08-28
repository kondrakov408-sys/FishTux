"""
TuxBrowser - Unit & Integration Test Suite
Verifies storage, interceptor blocklists, scheme handlers, and window creation.
"""

import os
import sys
import tempfile
import unittest
from urllib.parse import urlparse

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(BASE_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from browser.src.storage import TuxStorage
from browser.src.interceptor import TuxRequestInterceptor, DEFAULT_BLOCKLIST
from browser.src.scheme_handler import TuxSchemeHandler


class TestTuxStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = TuxStorage(data_dir=self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_settings_read_write(self):
        self.assertEqual(self.storage.get_setting("search_engine"), "TuxFind")
        self.storage.set_setting("search_engine", "DuckDuckGo")
        self.assertEqual(self.storage.get_setting("search_engine"), "DuckDuckGo")

    def test_bulk_settings_update(self):
        updates = {
            "security_level": "safest",
            "kill_switch_enabled": False,
            "block_trackers": True,
            "ghost_mode_type": "tor"
        }
        self.storage.update_settings(updates)
        for k, v in updates.items():
            self.assertEqual(self.storage.get_setting(k), v)

    def test_bookmarks(self):
        initial_count = len(self.storage.get_bookmarks())
        self.assertTrue(self.storage.add_bookmark("Arch Linux", "https://archlinux.org", "Linux"))
        self.assertTrue(self.storage.is_bookmarked("https://archlinux.org"))
        self.assertEqual(len(self.storage.get_bookmarks()), initial_count + 1)
        
        # Remove bookmark
        self.assertTrue(self.storage.remove_bookmark("https://archlinux.org"))
        self.assertFalse(self.storage.is_bookmarked("https://archlinux.org"))

    def test_history(self):
        self.storage.add_history("Kernel", "https://kernel.org")
        history = self.storage.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "https://kernel.org")
        
        # Delete item
        self.storage.delete_history_item("https://kernel.org")
        self.assertEqual(len(self.storage.get_history()), 0)

    def test_shield_stats_and_whitelist(self):
        self.assertFalse(self.storage.is_domain_whitelisted("example.com"))
        self.assertTrue(self.storage.toggle_domain_whitelist("example.com"))
        self.assertTrue(self.storage.is_domain_whitelisted("example.com"))
        
        # Untoggle
        self.assertFalse(self.storage.toggle_domain_whitelist("example.com"))
        self.assertFalse(self.storage.is_domain_whitelisted("example.com"))

    def test_unified_profile_export_import(self):
        # Add custom data
        self.storage.set_setting("search_engine", "DuckDuckGo")
        self.storage.add_bookmark("Custom Link", "https://custom.org")
        self.storage.add_history("Custom Visit", "https://custom.org/page")

        # Export profile
        profile = self.storage.export_profile_dict()
        self.assertEqual(profile["app"], "FishTux")
        self.assertEqual(profile["settings"]["search_engine"], "DuckDuckGo")
        self.assertTrue(any(b["title"] == "Custom Link" for b in profile["bookmarks"]))
        self.assertTrue(any(h["url"] == "https://custom.org/page" for h in profile["history"]))

        # Reset
        self.storage.reset_to_defaults()
        self.assertEqual(self.storage.get_setting("search_engine"), "TuxFind")

        # Import
        ok = self.storage.import_profile_dict(profile)
        self.assertTrue(ok)
        self.assertEqual(self.storage.get_setting("search_engine"), "DuckDuckGo")
        self.assertTrue(self.storage.is_bookmarked("https://custom.org"))


class TestTuxInterceptor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = TuxStorage(data_dir=self.temp_dir)
        self.interceptor = TuxRequestInterceptor(self.storage)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_blocklist_matching(self):
        # Known trackers
        self.assertTrue(self.interceptor.is_blocked("https://www.google-analytics.com/analytics.js", "example.com"))
        self.assertTrue(self.interceptor.is_blocked("https://stats.doubleclick.net/dc.js", "example.com"))
        self.assertTrue(self.interceptor.is_blocked("https://mc.yandex.ru/metrika/tag.js", "example.com"))
        self.assertTrue(self.interceptor.is_blocked("https://criteo.com/delivery/ajs.php", "example.com"))

        # Non-tracker / Safe URLs
        self.assertFalse(self.interceptor.is_blocked("https://kernel.org/pub/linux/kernel/", "kernel.org"))
        self.assertFalse(self.interceptor.is_blocked("https://wiki.archlinux.org/title/Main_page", "archlinux.org"))
        self.assertFalse(self.interceptor.is_blocked("tux://home", ""))

    def test_whitelist_bypass(self):
        # When domain is whitelisted, requests should not be blocked
        self.storage.toggle_domain_whitelist("trusted-site.com")
        self.assertFalse(self.interceptor.is_blocked("https://google-analytics.com/ga.js", "trusted-site.com"))


class TestTuxSchemeHandler(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = TuxStorage(data_dir=self.temp_dir)
        self.assets_dir = os.path.join(BASE_DIR, "assets")
        self.handler = TuxSchemeHandler(self.storage, self.assets_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_page_renders(self):
        home_html = self.handler._render_page("home").decode("utf-8")
        self.assertIn("FishTux", home_html)

        settings_html = self.handler._render_settings().decode("utf-8")
        self.assertIn("Настройки", settings_html)
        self.assertIn("saveAllSettings", settings_html)
        self.assertIn("saveAllBtnTop", settings_html)
        self.assertIn("block_ipv6_leaks", settings_html)

        about_html = self.handler._render_page("about").decode("utf-8")
        self.assertIn("TuxBrowser", about_html)

        shield_html = self.handler._render_shield().decode("utf-8")
        self.assertIn("Tux Shield", shield_html)

        search_html = self.handler._render_page("search").decode("utf-8")
        self.assertIn("TuxFind", search_html)


class TestTuxPrivacyFeatures(unittest.TestCase):
    def test_tracking_parameter_stripping(self):
        from browser.src.interceptor import strip_tracking_parameters

        # URL with UTM and advertising tracking identifiers
        dirty_url = "https://example.com/product?item=123&utm_source=facebook&utm_medium=cpc&gclid=xyz789&fbclid=abc1234&safe_param=true"
        clean_url = strip_tracking_parameters(dirty_url)

        self.assertNotIn("utm_source", clean_url)
        self.assertNotIn("utm_medium", clean_url)
        self.assertNotIn("gclid", clean_url)
        self.assertNotIn("fbclid", clean_url)
        self.assertIn("item=123", clean_url)
        self.assertIn("safe_param=true", clean_url)

        # URL without query
        self.assertEqual(strip_tracking_parameters("https://example.com/"), "https://example.com/")

    def test_anti_fingerprint_js(self):
        from browser.src.privacy_scripts import ANTI_FINGERPRINT_JS
        self.assertIn("globalPrivacyControl", ANTI_FINGERPRINT_JS)
        self.assertIn("doNotTrack", ANTI_FINGERPRINT_JS)
        self.assertIn("toDataURL", ANTI_FINGERPRINT_JS)
        self.assertIn("getBattery", ANTI_FINGERPRINT_JS)

    def test_ipv6_setting_default(self):
        temp_dir = tempfile.mkdtemp()
        storage = TuxStorage(data_dir=temp_dir)
        self.assertTrue(storage.get_setting("block_ipv6_leaks", True))
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


class TestTuxGhostManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = TuxStorage(data_dir=self.temp_dir)
        from browser.src.ghost_manager import TuxGhostManager
        self.ghost = TuxGhostManager(self.storage, self.temp_dir)

    def tearDown(self):
        self.ghost.shutdown()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ghost_enable_disable(self):
        from PySide6.QtNetwork import QNetworkProxy
        # Must start in direct mode (NoProxy) for safety and speed
        self.assertFalse(self.ghost.is_ghost_active)
        self.assertEqual(self.ghost.current_mode, "direct")

        # Custom Proxy Mode
        self.ghost.enable_ghost_mode("custom", "socks5://127.0.0.1:10808")
        self.assertTrue(self.ghost.is_ghost_active)
        self.assertEqual(self.ghost.current_mode, "custom")
        proxy = QNetworkProxy.applicationProxy()
        self.assertEqual(proxy.type(), QNetworkProxy.ProxyType.Socks5Proxy)
        self.assertEqual(proxy.port(), 10808)

        # Disable -> Restores NoProxy immediately
        self.ghost.disable_ghost_mode()
        self.assertFalse(self.ghost.is_ghost_active)
        proxy_off = QNetworkProxy.applicationProxy()
        self.assertEqual(proxy_off.type(), QNetworkProxy.ProxyType.NoProxy)

    def test_custom_proxy(self):
        from PySide6.QtNetwork import QNetworkProxy
        self.ghost.enable_ghost_mode("custom", "http://192.168.1.100:8080")
        self.assertEqual(self.ghost.current_mode, "custom")
        proxy = QNetworkProxy.applicationProxy()
        self.assertEqual(proxy.type(), QNetworkProxy.ProxyType.HttpProxy)
        self.assertEqual(proxy.hostName(), "192.168.1.100")
        self.assertEqual(proxy.port(), 8080)

    def test_ghost_state_restoration(self):
        # Enable ghost mode and verify saved flag
        self.ghost.enable_ghost_mode("custom", "socks5://127.0.0.1:9050")
        self.assertTrue(self.storage.get_setting("ghost_active"))
        self.assertEqual(self.storage.get_setting("ghost_mode_type"), "custom")

        # Create a new ghost manager simulating next app launch
        from browser.src.ghost_manager import TuxGhostManager
        new_ghost = TuxGhostManager(self.storage, self.temp_dir)
        new_ghost.restore_saved_state()
        self.assertTrue(new_ghost.is_ghost_active)
        self.assertEqual(new_ghost.current_mode, "custom")
        new_ghost.shutdown()

    def test_transport_discovery(self):
        transports = self.ghost.get_available_transports()
        self.assertIn("webtunnel", transports)
        self.assertIn("obfs4", transports)
        self.assertIn("snowflake", transports)


class TestTuxUrlResolution(unittest.TestCase):
    def test_direct_url_detection(self):
        from browser.src.interceptor import is_direct_url, resolve_input_to_url

        # Domains and paths
        self.assertTrue(is_direct_url("2ip.ru"))
        self.assertTrue(is_direct_url("google.com/search?q=test"))
        self.assertTrue(is_direct_url("https://kernel.org"))
        self.assertTrue(is_direct_url("http://192.168.1.1:8080/index.html"))
        self.assertTrue(is_direct_url("localhost:3000"))
        self.assertTrue(is_direct_url("tux://settings"))

        # Search queries
        self.assertFalse(is_direct_url("hello world"))
        self.assertFalse(is_direct_url("what is linux"))
        self.assertFalse(is_direct_url("download arch linux iso"))

        # URL Resolution
        self.assertEqual(resolve_input_to_url("2ip.ru"), "https://2ip.ru")
        self.assertEqual(resolve_input_to_url("localhost:8080"), "http://localhost:8080")
        self.assertEqual(resolve_input_to_url("https://github.com"), "https://github.com")
        self.assertEqual(resolve_input_to_url("tux browser search", "tux://search?q={query}"), "tux://search?q=tux+browser+search")


class TestTimezoneSpoofing(unittest.TestCase):
    def test_js_timezone_alignment(self):
        import subprocess, json
        from browser.src.privacy_scripts import get_anti_fingerprint_js

        tz = "America/North_Dakota/Beulah"
        js = get_anti_fingerprint_js(tz)
        test_script = js + """
        const d = new Date("2026-08-28T17:15:00Z");
        const intl = new Intl.DateTimeFormat();
        const intlRu = new Intl.DateTimeFormat("ru-RU");
        const results = {
            "tz": intl.resolvedOptions().timeZone,
            "toTimeString": d.toTimeString(),
            "toString": d.toString(),
            "toDateString": d.toDateString(),
            "toLocaleString": d.toLocaleString("ru-RU"),
            "toLocaleTimeString": d.toLocaleTimeString("en-US", { hour12: false }),
            "toLocaleDateString": d.toLocaleDateString("ru-RU"),
            "offset": d.getTimezoneOffset(),
            "hours": d.getHours(),
            "minutes": d.getMinutes(),
            "ruFormat": intlRu.format(d)
        };
        console.log(JSON.stringify(results));
        """
        res = subprocess.run(["node", "-e", test_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Node script error: {res.stderr}")
        data = json.loads(res.stdout.strip())
        self.assertEqual(data["tz"], tz)
        self.assertEqual(data["hours"], 12)
        self.assertEqual(data["minutes"], 15)
        self.assertEqual(data["offset"], 300)
        self.assertIn("12:15:00", data["toTimeString"])
        self.assertIn("12:15:00", data["toLocaleTimeString"])
        self.assertIn("12:15:00", data["toLocaleString"])
        self.assertIn("28.08.2026", data["toLocaleDateString"])
        self.assertIn("Fri Aug 28 2026", data["toString"])

    def test_tokyo_timezone_alignment(self):
        import subprocess, json
        from browser.src.privacy_scripts import get_anti_fingerprint_js

        tz = "Asia/Tokyo"
        js = get_anti_fingerprint_js(tz)
        test_script = js + """
        const d = new Date("2026-08-28T17:15:00Z");
        const intl = new Intl.DateTimeFormat();
        const results = {
            "tz": intl.resolvedOptions().timeZone,
            "hours": d.getHours(),
            "date": d.getDate(),
            "offset": d.getTimezoneOffset()
        };
        console.log(JSON.stringify(results));
        """
        res = subprocess.run(["node", "-e", test_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Node script error: {res.stderr}")
        data = json.loads(res.stdout.strip())
        self.assertEqual(data["tz"], tz)
        # UTC 17:15 on 28th + 9 hours -> 02:15 on 29th
        self.assertEqual(data["hours"], 2)
        self.assertEqual(data["date"], 29)
        self.assertEqual(data["offset"], -540)

    def test_language_alignment(self):
        import subprocess, json
        from browser.src.privacy_scripts import get_anti_fingerprint_js

        tz = "Europe/Stockholm"
        lang = "sv-SE"
        langs = ["sv-SE", "sv", "en-US", "en"]
        js = get_anti_fingerprint_js(tz, lang, langs)
        test_script = js + """
        const results = {
            "lang": navigator.language,
            "languages": navigator.languages
        };
        console.log(JSON.stringify(results));
        """
        res = subprocess.run(["node", "-e", test_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Node script error: {res.stderr}")
        data = json.loads(res.stdout.strip())
        self.assertEqual(data["lang"], "sv-SE")
        self.assertEqual(data["languages"], ["sv-SE", "sv", "en-US", "en"])


if __name__ == "__main__":
    unittest.main()

