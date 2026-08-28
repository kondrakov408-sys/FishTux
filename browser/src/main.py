"""
TuxBrowser - Entry Point
Registers tux:// scheme, initializes WebEngine profiles, request interceptor, and runs the application.
"""

import sys
import os
import time
import argparse

# Force standard Tor-grade UTC timezone at POSIX C-runtime level
os.environ["TZ"] = "UTC"
try:
    time.tzset()
except Exception:
    pass

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(BASE_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Sanitize proxy variables: Chromium fails with ERR_TOO_MANY_RETRIES when socks5 proxies have embedded user:password
for var in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    val = os.environ.get(var, "")
    if "socks5://" in val:
        os.environ.pop(var, None)

os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"

# Hardened C++ Chromium Engine Flags (Kills WebRTC UDP leaks, background telemetry, and prefetching at binary level)
HARDENED_CHROMIUM_FLAGS = [
    "--enable-gpu-rasterization",
    "--ignore-gpu-blocklist",
    # 1. WebRTC total elimination at C++ network stack
    "--disable-webrtc",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    # 2. Eliminate all background upstream Google telemetries & pings
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--disable-sync",
    "--no-pings",
    "--disable-breakpad",
    "--disable-features=Translate,OptimizationHints,MediaRouter,CalculateNativeWinOcclusion,AutofillServerCommunication,InterestFeedContentSuggestions",
    # 3. Prevent DNS leaks and preconnects at C++ resolver level
    "--disable-dns-prefetch",
    "--disable-dns-reconnection",
    "--disable-preconnect"
]

existing_flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = f"{' '.join(HARDENED_CHROMIUM_FLAGS)} {existing_flags}".strip()

from PySide6.QtWebEngineCore import (
    QWebEngineUrlScheme,
    QWebEngineProfile,
    QWebEngineSettings
)
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QCoreApplication

from browser.src.storage import TuxStorage
from browser.src.interceptor import TuxRequestInterceptor
from browser.src.scheme_handler import TuxSchemeHandler
from browser.src.window import TuxBrowserWindow


def register_schemes():
    """Custom schemes MUST be registered before Q(Core)Application instantiation."""
    scheme = QWebEngineUrlScheme(b"tux")
    scheme.setFlags(
        QWebEngineUrlScheme.Flag.SecureScheme |
        QWebEngineUrlScheme.Flag.LocalAccessAllowed |
        QWebEngineUrlScheme.Flag.ViewSourceAllowed |
        QWebEngineUrlScheme.Flag.CorsEnabled |
        QWebEngineUrlScheme.Flag.FetchApiAllowed
    )
    scheme.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    QWebEngineUrlScheme.registerScheme(scheme)


def ensure_tuxfind_running():
    """Checks if TuxFind backend is listening on localhost:8080. If not, spawns it."""
    import subprocess
    import socket
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.4)
    result = sock.connect_ex(('127.0.0.1', 8080))
    sock.close()
    if result == 0:
        return None

    tuxfind_bin = os.path.join(ROOT_DIR, "TuxFind", "tuxfind")
    if os.path.exists(tuxfind_bin):
        try:
            proc = subprocess.Popen([tuxfind_bin], cwd=os.path.join(ROOT_DIR, "TuxFind"))
            return proc
        except Exception as e:
            print(f"[TuxBrowser] Could not auto-start TuxFind: {e}")
    return None


def main():
    # 1. Register custom tux:// scheme first
    register_schemes()

    # 2. Ensure TuxFind search engine is running in background
    tuxfind_proc = ensure_tuxfind_running()

    # 3. CLI Arguments
    parser = argparse.ArgumentParser(description="TuxBrowser - Secure Linux Web Browser 🐧")
    parser.add_argument("url", nargs="?", default="tux://home", help="Initial URL to open")
    parser.add_argument("--ghost", "--incognito", action="store_true", help="Launch in private Ghost Mode")
    parser.add_argument("--safe-mode", action="store_true", help="Launch in safe mode without custom rules")
    args = parser.parse_args()

    # 4. High DPI & Font rendering policy (must be before QApplication)
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    # 5. Create Qt Application
    app = QApplication(sys.argv)
    app.setApplicationName("TuxBrowser")
    app.setApplicationDisplayName("TuxBrowser 🐧")
    app.setOrganizationName("LinuxTux")

    # 5. Storage & Assets Directory
    assets_dir = os.path.join(BASE_DIR, "assets")
    storage = TuxStorage()

    # 6. Ghost Manager (Tor & Network Routing)
    from browser.src.ghost_manager import TuxGhostManager
    ghost_manager = TuxGhostManager(storage, storage.data_dir)

    # 7. Request Interceptor (Tux Shield)
    interceptor = TuxRequestInterceptor(storage, ghost_manager=ghost_manager)

    # 8. WebEngine Profile setup
    if args.ghost:
        profile = QWebEngineProfile(app)  # In-memory off-the-record profile
        ghost_manager.enable_ghost_mode("tor")
    else:
        profile = QWebEngineProfile.defaultProfile()
        ghost_manager.restore_saved_state()

    # Install Scheme Handler for tux://
    scheme_handler = TuxSchemeHandler(storage, assets_dir, profile, ghost_manager)
    profile.installUrlSchemeHandler(b"tux", scheme_handler)

    # Install Tux Shield Interceptor
    profile.setUrlRequestInterceptor(interceptor)

    # Apply Privacy & Network Settings on profile
    from browser.src.privacy_scripts import install_privacy_scripts
    saved_tz = storage.get_setting("active_timezone", "Europe/Amsterdam")
    saved_lang = storage.get_setting("active_language", "en-US")
    saved_langs = storage.get_setting("active_languages", ["en-US", "en"])
    install_privacy_scripts(profile, saved_tz, saved_lang, saved_langs)

    # Disable DNS leaks, hyperlink ping tracking, and restrict WebRTC to public interfaces only
    p_settings = profile.settings()
    p_settings.setAttribute(QWebEngineSettings.WebAttribute.DnsPrefetchEnabled, False)
    p_settings.setAttribute(QWebEngineSettings.WebAttribute.HyperlinkAuditingEnabled, False)
    p_settings.setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, True)

    if not args.ghost:
        web_data_dir = os.path.join(storage.data_dir, "web_profile")
        os.makedirs(web_data_dir, exist_ok=True)
        profile.setPersistentStoragePath(web_data_dir)
        profile.setCachePath(os.path.join(web_data_dir, "cache"))
        profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies)

    ua = storage.get_setting("custom_user_agent")
    if ua and "Firefox" not in ua:
        profile.setHttpUserAgent(ua)

    # 9. Create & Show Main Window
    window = TuxBrowserWindow(profile, storage, interceptor, ghost_manager, assets_dir, is_incognito=args.ghost)
    
    if args.url and args.url != "tux://home":
        # Navigate first tab to requested URL
        tab = window.current_tab()
        if tab:
            window.open_url(args.url)

    window.show()

    # 10. Execution loop
    exit_code = app.exec()

    # Clean up on exit
    ghost_manager.shutdown()
    if storage.get_setting("clear_history_on_exit", False):
        storage.clear_history()

    if tuxfind_proc:
        try:
            tuxfind_proc.terminate()
            tuxfind_proc.wait(timeout=1.0)
        except Exception:
            pass

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
