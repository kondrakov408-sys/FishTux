"""
TuxBrowser - Ghost Privacy & Tor Manager
Handles zero-config Tor routing, IP rotation (New Identity), Custom SOCKS5/HTTP proxies,
and WebRTC/DNS leak prevention without blocking the main GUI thread.
"""

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, ProxyHandler, build_opener

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QNetworkProxy

COUNTRY_LANG_MAP = {
    "SE": ("sv-SE", ["sv-SE", "sv", "en-US", "en"]),
    "DE": ("de-DE", ["de-DE", "de", "en-US", "en"]),
    "FR": ("fr-FR", ["fr-FR", "fr", "en-US", "en"]),
    "IT": ("it-IT", ["it-IT", "it", "en-US", "en"]),
    "ES": ("es-ES", ["es-ES", "es", "en-US", "en"]),
    "NL": ("nl-NL", ["nl-NL", "nl", "en-US", "en"]),
    "PL": ("pl-PL", ["pl-PL", "pl", "en-US", "en"]),
    "RU": ("ru-RU", ["ru-RU", "ru", "en-US", "en"]),
    "UA": ("uk-UA", ["uk-UA", "uk", "en-US", "en"]),
    "BY": ("be-BY", ["be-BY", "be", "ru", "en-US", "en"]),
    "KZ": ("kk-KZ", ["kk-KZ", "kk", "ru", "en-US", "en"]),
    "AT": ("de-AT", ["de-AT", "de", "en-US", "en"]),
    "CH": ("de-CH", ["de-CH", "de", "fr", "en-US", "en"]),
    "GB": ("en-GB", ["en-GB", "en-US", "en"]),
    "US": ("en-US", ["en-US", "en"]),
    "CA": ("en-CA", ["en-CA", "en-US", "fr-CA", "en"]),
    "AU": ("en-AU", ["en-AU", "en-US", "en"]),
    "JP": ("ja-JP", ["ja-JP", "ja", "en-US", "en"]),
    "KR": ("ko-KR", ["ko-KR", "ko", "en-US", "en"]),
    "CN": ("zh-CN", ["zh-CN", "zh", "en-US", "en"]),
    "BR": ("pt-BR", ["pt-BR", "pt", "en-US", "en"]),
    "TR": ("tr-TR", ["tr-TR", "tr", "en-US", "en"]),
    "FI": ("fi-FI", ["fi-FI", "fi", "en-US", "en"]),
    "NO": ("nb-NO", ["nb-NO", "no", "nn", "en-US", "en"]),
    "DK": ("da-DK", ["da-DK", "da", "en-US", "en"]),
    "CZ": ("cs-CZ", ["cs-CZ", "cs", "en-US", "en"]),
    "RO": ("ro-RO", ["ro-RO", "ro", "en-US", "en"]),
    "HU": ("hu-HU", ["hu-HU", "hu", "en-US", "en"]),
    "GR": ("el-GR", ["el-GR", "el", "en-US", "en"]),
    "PT": ("pt-PT", ["pt-PT", "pt", "en-US", "en"]),
    "BG": ("bg-BG", ["bg-BG", "bg", "en-US", "en"]),
    "IN": ("en-IN", ["en-IN", "hi", "en-GB", "en"]),
    "IL": ("he-IL", ["he-IL", "he", "en-US", "en"]),
    "SG": ("en-SG", ["en-SG", "zh-SG", "en"]),
    "MX": ("es-MX", ["es-MX", "es", "en-US", "en"]),
    "AR": ("es-AR", ["es-AR", "es", "en-US", "en"]),
    "CL": ("es-CL", ["es-CL", "es", "en-US", "en"]),
    "BE": ("nl-BE", ["nl-BE", "fr-BE", "nl", "fr", "en-US", "en"]),
}


def get_country_languages(country_code: str) -> Tuple[str, list]:
    """Resolves primary language and language fallback list for a country code."""
    code = (country_code or "").upper().strip()
    if code in COUNTRY_LANG_MAP:
        return COUNTRY_LANG_MAP[code]
    return ("en-US", ["en-US", "en"])


class TuxGhostManager(QObject):
    """Manages ghost network routing, Tor lifecycle, and identity rotation."""

    status_changed = Signal(dict)
    ip_updated = Signal(str, str) # ip, country
    tz_updated = Signal(str)      # timezone (e.g. Europe/Amsterdam)
    lang_updated = Signal(str, list) # primary_lang, languages_list
    tor_error = Signal(str)

    def __init__(self, storage, base_data_dir: str):
        super().__init__()
        self.storage = storage
        self.data_dir = os.path.join(base_data_dir, "tor_ghost")
        os.makedirs(self.data_dir, exist_ok=True)

        self.tor_socks_port = 9052
        self.tor_control_port = 9053
        self.tor_http_port = 9054
        self.tor_proc: Optional[subprocess.Popen] = None
        self.is_tor_running = False
        self.bootstrap_status = "Выключен"
        self.is_bootstrapped = False

        # Load persisted settings but always start in Direct mode for safety unless explicit
        settings = self.storage.get_settings()
        self.current_mode = "direct"
        self.is_ghost_active = False
        self.custom_proxy_str = settings.get("ghost_custom_proxy", "")
        self.tor_bridges = settings.get("tor_bridges", "")

        self.last_detected_ip = "Прямое подключение"
        self.last_detected_country = "Локальный IP"

        # Ensure direct connection by default until state is restored
        QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))

    def restore_saved_state(self) -> None:
        """Restores ghost mode if it was active in the previous session."""
        settings = self.storage.get_settings()
        was_active = settings.get("ghost_active", False)
        saved_mode = settings.get("ghost_mode_type", "tor")
        saved_proxy = settings.get("ghost_custom_proxy", "")
        if was_active:
            print(f"[TuxGhost] Restoring saved Ghost Mode state on startup ({saved_mode})")
            self.enable_ghost_mode(saved_mode, saved_proxy)

    def enable_ghost_mode(self, mode: str = "tor", custom_proxy: str = "") -> bool:
        """Enables Ghost Mode (Tor or Custom Proxy) asynchronously."""
        self.current_mode = mode
        if custom_proxy:
            self.custom_proxy_str = custom_proxy

        self.is_ghost_active = True
        self.storage.update_settings({
            "ghost_active": True,
            "ghost_mode_type": mode,
            "ghost_custom_proxy": self.custom_proxy_str
        })

        if mode == "custom" and self.custom_proxy_str:
            return self._apply_custom_proxy(self.custom_proxy_str)
        elif mode == "tor":
            self.bootstrap_status = "Запуск Tor и проверка соединения..."
            self._emit_status()
            threading.Thread(target=self._start_and_bootstrap_tor, daemon=True).start()
            return True
        else:
            self.disable_ghost_mode()
            return False

    def _find_transport_binary(self, transport_type: str) -> Optional[str]:
        """Searches for pluggable transport binary in all standard user and system locations."""
        t_type = transport_type.lower().strip()
        names = []
        if t_type == "webtunnel":
            names = ["webtunnel-client", "webtunnel", "webtunnel-go"]
        elif t_type == "obfs4":
            names = ["obfs4proxy", "lyrebird", "obfs4"]
        elif t_type == "snowflake":
            names = ["snowflake-client", "snowflake"]
        elif t_type == "conjure":
            names = ["conjure-client", "conjure"]
        elif t_type == "meek":
            names = ["meek-client", "meek"]
        else:
            names = [t_type, f"{t_type}-client"]

        search_dirs = [
            os.path.expanduser("~/.local/bin"),
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/lib/tor",
            "/usr/libexec/tor",
            "/usr/lib/cni",
            "/opt/tor-browser/Browser/TorBrowser/Tor/PluggableTransports",
            os.path.expanduser("~/.local/share/tor"),
        ]

        for name in names:
            for d in search_dirs:
                path = os.path.join(d, name)
                if os.path.exists(path) and os.access(path, os.X_OK):
                    return path
            which_path = shutil.which(name)
            if which_path:
                return which_path

        return None

    def get_available_transports(self) -> Dict[str, Optional[str]]:
        """Returns detected pluggable transports and their binary paths."""
        return {
            "webtunnel": self._find_transport_binary("webtunnel"),
            "obfs4": self._find_transport_binary("obfs4"),
            "snowflake": self._find_transport_binary("snowflake")
        }

    def _start_and_bootstrap_tor(self):
        """Starts Tor in background and only applies proxy once 100% connected."""
        tor_binary = shutil.which("tor")
        if not tor_binary:
            self.bootstrap_status = "Ошибка: tor не установлен в системе"
            self.tor_error.emit(self.bootstrap_status)
            self._emit_status()
            return

        # Ensure latest bridges from storage are loaded
        self.tor_bridges = self.storage.get_setting("tor_bridges", self.tor_bridges)

        torrc_path = os.path.join(self.data_dir, "torrc")
        lines = [
            f"SocksPort {self.tor_socks_port}",
            f"ControlPort {self.tor_control_port}",
            f"HTTPTunnelPort {self.tor_http_port}",
            "CookieAuthentication 0",
            f"DataDirectory {self.data_dir}",
            "Log notice stdout",
            "ClientOnly 1",
            "AvoidDiskWrites 1",
            "ClientUseIPv6 1"
        ]

        if self.tor_bridges and self.tor_bridges.strip():
            lines.append("UseBridges 1")
            
            raw_lines = [
                l.replace("\r", "").strip() 
                for l in self.tor_bridges.split("\n") 
                if l.replace("\r", "").strip() and not l.strip().startswith("#")
            ]

            needed_transports = set()
            clean_bridge_lines = []

            for raw_b in raw_lines:
                # Remove any existing 'Bridge ' or 'bridge ' prefix (case-insensitive)
                b_clean = raw_b
                if b_clean.lower().startswith("bridge "):
                    b_clean = b_clean[7:].strip()
                
                if not b_clean:
                    continue

                parts = b_clean.split()
                first_word = parts[0].lower() if parts else ""
                
                # Check for incomplete/invalid webtunnel lines (e.g. url= without url)
                if first_word == "webtunnel" and ("url=" in b_clean):
                    if "url=http" not in b_clean:
                        # Broken or empty url parameter
                        continue

                if first_word in ("webtunnel", "obfs4", "snowflake", "conjure", "meek"):
                    needed_transports.add(first_word)
                
                clean_bridge_lines.append(f"Bridge {b_clean}")

            # Resolve transport binaries
            missing_transports = []
            for t in needed_transports:
                bin_path = self._find_transport_binary(t)
                if bin_path:
                    lines.append(f"ClientTransportPlugin {t} exec {bin_path}")
                else:
                    missing_transports.append(t)

            if missing_transports:
                missing_str = ", ".join(missing_transports)
                self.bootstrap_status = f"⚠️ Не найден плагин транспорта Tor: {missing_str} (установите {missing_str}-client в ~/.local/bin/)"
                print(f"[TuxGhost] Pluggable transport missing: {missing_str}")
                self.tor_error.emit(self.bootstrap_status)
                self._emit_status()
                return

            if clean_bridge_lines:
                lines.extend(clean_bridge_lines)
            else:
                # If bridges were provided but all invalid, remove UseBridges
                lines = [l for l in lines if l != "UseBridges 1"]

        try:
            with open(torrc_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            if self.tor_proc and self.tor_proc.poll() is None:
                try:
                    self.tor_proc.terminate()
                    self.tor_proc.wait(timeout=1.0)
                except Exception:
                    pass

            # Failsafe kill of any orphan processes on our config
            try:
                subprocess.run(["pkill", "-9", "-f", torrc_path], capture_output=True)
                time.sleep(0.3)
            except Exception:
                pass

            # Prepare PATH environment and clean proxy variables so PT connects directly
            tor_env = os.environ.copy()
            for var in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "socks_proxy", "SOCKS_PROXY"]:
                tor_env.pop(var, None)

            current_path = tor_env.get("PATH", "")
            extra_paths = [os.path.expanduser("~/.local/bin"), "/usr/local/bin", "/usr/bin", "/bin"]
            for ep in extra_paths:
                if ep not in current_path.split(":"):
                    current_path = f"{ep}:{current_path}"
            tor_env["PATH"] = current_path

            self.tor_proc = subprocess.Popen(
                [tor_binary, "-f", torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=tor_env
            )
            self.is_tor_running = True
        except Exception as e:
            self.bootstrap_status = f"Ошибка: {e}"
            self.tor_error.emit(self.bootstrap_status)
            self._emit_status()
            return

        # Monitor bootstrap
        start_time = time.time()
        connected = False
        try:
            for line in iter(self.tor_proc.stdout.readline, ''):
                if not line:
                    break
                line_str = line.strip()
                if "Bootstrapped 100%" in line_str:
                    connected = True
                    self.is_bootstrapped = True
                    self.is_ghost_active = True
                    self.current_mode = "tor"
                    self.bootstrap_status = "🟢 Подключено (Tor 100%)"
                    print("[TuxGhost] Tor bootstrapped 100%!")
                    
                    proxy = QNetworkProxy()
                    proxy.setType(QNetworkProxy.ProxyType.Socks5Proxy)
                    proxy.setHostName("127.0.0.1")
                    proxy.setPort(self.tor_socks_port)
                    QNetworkProxy.setApplicationProxy(proxy)
                    self._emit_status()
                    self.async_check_ip()
                    break
                elif "Bootstrapped" in line_str:
                    # Extract percentage: e.g. "Bootstrapped 45% (requesting_descriptors)"
                    parts = line_str.split("Bootstrapped ", 1)
                    if len(parts) > 1:
                        self.bootstrap_status = f"Tor {parts[1].split(':', 1)[0].strip()}"
                    else:
                        self.bootstrap_status = line_str.split(":", 1)[-1].strip()
                    self._emit_status()

                if time.time() - start_time > 120 and not connected:
                    break
        except Exception:
            pass

        if not connected:
            self.is_ghost_active = False
            self.is_bootstrapped = False
            self.bootstrap_status = "⚠️ Мост не отвечает или заблокирован DPI. Попробуйте другой мост или SOCKS5."
            print("[TuxGhost] Tor connection timeout with active bridges.")
            self.tor_error.emit(self.bootstrap_status)
            QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))
            self._emit_status()

    def _apply_custom_proxy(self, custom_proxy: str) -> bool:
        """Applies a custom SOCKS5/HTTP proxy."""
        try:
            parsed = urlparse(custom_proxy if "://" in custom_proxy else f"socks5://{custom_proxy}")
            scheme = parsed.scheme.lower()
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 1080

            proxy = QNetworkProxy()
            if "http" in scheme:
                proxy.setType(QNetworkProxy.ProxyType.HttpProxy)
            else:
                proxy.setType(QNetworkProxy.ProxyType.Socks5Proxy)

            proxy.setHostName(host)
            proxy.setPort(port)
            if parsed.username:
                proxy.setUser(parsed.username)
            if parsed.password:
                proxy.setPassword(parsed.password)

            QNetworkProxy.setApplicationProxy(proxy)
            self.is_ghost_active = True
            self.bootstrap_status = f"🟢 Пользовательский прокси ({host}:{port})"
            print(f"[TuxGhost] Applied Custom Proxy -> {scheme}://{host}:{port}")
            self._emit_status()
            self.async_check_ip()
            return True
        except Exception as e:
            print(f"[TuxGhost] Failed to parse custom proxy: {e}")
            self.bootstrap_status = f"Ошибка формата: {e}"
            self.tor_error.emit(self.bootstrap_status)
            return False

    def disable_ghost_mode(self) -> None:
        """Disables Ghost Mode and returns to direct connection."""
        self.is_ghost_active = False
        self.current_mode = "direct"
        self.bootstrap_status = "Выключен"
        self.storage.update_settings({
            "ghost_active": False,
            "ghost_mode_type": "direct"
        })
        QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))
        print("[TuxGhost] Direct connection restored (NoProxy)")
        self._emit_status()
        self.async_check_ip()

    def toggle_ghost_mode(self) -> bool:
        """Toggles between Ghost and Direct mode."""
        if self.is_ghost_active:
            self.disable_ghost_mode()
            return False
        else:
            self.enable_ghost_mode(self.current_mode if self.current_mode != "direct" else "tor")
            return True

    def rotate_identity(self) -> Tuple[bool, str]:
        """Sends SIGNAL NEWNYM to Tor Control Port to immediately acquire a new IP."""
        if not self.is_ghost_active:
            self.enable_ghost_mode("tor")
            return True, "Включение Tux Ghost и запрос нового IP..."

        if self.current_mode != "tor":
            return False, "Ротация доступна только в режиме Tor Ghost"

        success = False
        ports_to_try = [self.tor_control_port, 9053, 9051]
        for port in ports_to_try:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.5)
                s.connect(("127.0.0.1", port))
                s.sendall(b'AUTHENTICATE ""\r\n')
                auth = s.recv(512).decode("utf-8", errors="ignore")
                if "250" not in auth:
                    s.sendall(b'AUTHENTICATE\r\n')
                    auth = s.recv(512).decode("utf-8", errors="ignore")
                
                s.sendall(b'SIGNAL NEWNYM\r\n')
                resp = s.recv(512).decode("utf-8", errors="ignore")
                s.close()
                if "250" in resp or "250" in auth:
                    print(f"[TuxGhost] Tor identity rotated successfully via port {port}!")
                    success = True
                    break
            except Exception:
                pass

        # Schedule GeoIP check after short delay so Tor circuit switches
        def _delayed_check():
            time.sleep(1.5)
            self._check_ip_worker()

        threading.Thread(target=_delayed_check, daemon=True).start()

        if success:
            return True, "Личность обновлена! Новый IP и маршрут активны."
        return True, "Сигнал смены маршрута передан в сеть Tor."

    def async_check_ip(self) -> None:
        """Queries IP & country in background thread to avoid UI freeze."""
        threading.Thread(target=self._check_ip_worker, daemon=True).start()

    def _fetch_geoip_json(self, url: str) -> Optional[dict]:
        """Fetches GeoIP JSON data routing through active proxy/Tor or directly."""
        # Method 1: If Tor is active or in tor mode with bootstrapped daemon, use curl with --socks5-hostname
        if (self.current_mode == "tor" or self.is_ghost_active) and self.is_bootstrapped:
            if shutil.which("curl"):
                try:
                    res = subprocess.run(
                        ["curl", "-s", "-m", "5", "--socks5-hostname", f"127.0.0.1:{self.tor_socks_port}", url],
                        capture_output=True,
                        text=True,
                        timeout=6
                    )
                    if res.returncode == 0 and res.stdout.strip().startswith("{"):
                        return json.loads(res.stdout.strip())
                except Exception:
                    pass
        elif self.is_ghost_active and self.current_mode == "custom" and self.custom_proxy_str:
            if shutil.which("curl"):
                try:
                    res = subprocess.run(
                        ["curl", "-s", "-m", "5", "-x", self.custom_proxy_str, url],
                        capture_output=True,
                        text=True,
                        timeout=6
                    )
                    if res.returncode == 0 and res.stdout.strip().startswith("{"):
                        return json.loads(res.stdout.strip())
                except Exception:
                    pass

        # Method 2: Standard urllib (with HTTPTunnel if Tor, or direct)
        try:
            if (self.current_mode == "tor" or self.is_ghost_active) and self.is_bootstrapped:
                proxy_handler = ProxyHandler({
                    "http": f"http://127.0.0.1:{self.tor_http_port}",
                    "https": f"http://127.0.0.1:{self.tor_http_port}"
                })
            elif self.is_ghost_active and self.current_mode == "custom" and self.custom_proxy_str and ("http://" in self.custom_proxy_str or "https://" in self.custom_proxy_str):
                proxy_handler = ProxyHandler({"http": self.custom_proxy_str, "https": self.custom_proxy_str})
            else:
                proxy_handler = ProxyHandler({})

            opener = build_opener(proxy_handler)
            req = Request(url, headers={"User-Agent": "TuxBrowser/2.0"})
            with opener.open(req, timeout=4.0) as resp:
                raw = resp.read().decode("utf-8")
                if raw.strip().startswith("{"):
                    return json.loads(raw)
        except Exception:
            pass

        return None

    def _check_ip_worker(self) -> None:
        ip = ""
        country = ""
        country_code = ""
        timezone = ""

        endpoints = [
            ("https://ipwho.is/", lambda d: (
                d.get("ip", ""),
                d.get("country", ""),
                d.get("country_code", ""),
                d.get("timezone", {}).get("id", "") if isinstance(d.get("timezone"), dict) else d.get("timezone", "")
            )),
            ("https://ipinfo.io/json", lambda d: (
                d.get("ip", ""),
                d.get("country", ""),
                d.get("country", ""),
                d.get("timezone", "")
            )),
            ("https://freeipapi.com/api/json", lambda d: (
                d.get("ipAddress", ""),
                d.get("countryName", ""),
                d.get("countryCode", ""),
                d.get("timeZone", "")
            )),
            ("http://ip-api.com/json", lambda d: (
                d.get("query", ""),
                d.get("country", ""),
                d.get("countryCode", ""),
                d.get("timezone", "")
            )),
            ("https://ipapi.co/json/", lambda d: (
                d.get("ip", ""),
                d.get("country_name", ""),
                d.get("country_code", ""),
                d.get("timezone", "")
            ))
        ]

        for url, parser in endpoints:
            try:
                data = self._fetch_geoip_json(url)
                if data and isinstance(data, dict):
                    parsed_ip, parsed_country, parsed_code, parsed_tz = parser(data)
                    if parsed_ip:
                        ip = parsed_ip
                        if parsed_country:
                            country = parsed_country
                        if parsed_code:
                            country_code = parsed_code
                        if parsed_tz:
                            timezone = parsed_tz
                        break
            except Exception:
                continue

        # If IP was detected but timezone/country_code is missing, query direct IP lookup
        if ip and (not timezone or not country_code):
            for fallback_url, parser in [
                (f"https://ipwho.is/{ip}", lambda d: (
                    d.get("timezone", {}).get("id", "") if isinstance(d.get("timezone"), dict) else d.get("timezone", ""),
                    d.get("country_code", "")
                )),
                (f"https://ipinfo.io/{ip}/json", lambda d: (d.get("timezone", ""), d.get("country", "")))
            ]:
                try:
                    data = self._fetch_geoip_json(fallback_url)
                    if data and isinstance(data, dict):
                        tz_val, code_val = parser(data)
                        if tz_val and not timezone:
                            timezone = tz_val
                        if code_val and not country_code:
                            country_code = code_val
                        if timezone and country_code:
                            break
                except Exception:
                    pass

        if ip:
            self.last_detected_ip = ip
            self.last_detected_country = country or ("Tor Узел" if self.is_ghost_active else "Прямое соединение")
        else:
            if self.is_ghost_active:
                self.last_detected_ip = "Скрыт"
                self.last_detected_country = "Анонимный маршрут"
            else:
                self.last_detected_ip = "Прямое подключение"
                self.last_detected_country = "Локальный интернет"

        if timezone:
            self.storage.set_setting("active_timezone", timezone)
            self.tz_updated.emit(timezone)
            print(f"[TuxGhost] Precision Timezone Aligned to IP GeoIP -> {timezone}")

        if country_code:
            primary_lang, languages = get_country_languages(country_code)
            self.storage.set_setting("active_language", primary_lang)
            self.storage.set_setting("active_languages", languages)
            self.lang_updated.emit(primary_lang, languages)
            print(f"[TuxGhost] Precision Language Aligned to IP GeoIP ({country_code}) -> {primary_lang} ({languages})")

        self.ip_updated.emit(self.last_detected_ip, self.last_detected_country)
        self._emit_status()

    def _emit_status(self) -> None:
        st = self.get_status()
        self.status_changed.emit(st)

    def get_status(self) -> Dict:
        return {
            "is_active": self.is_ghost_active,
            "mode": self.current_mode,
            "custom_proxy": self.custom_proxy_str,
            "ip": self.last_detected_ip,
            "country": self.last_detected_country,
            "bootstrap_status": self.bootstrap_status,
            "is_bootstrapped": self.is_bootstrapped
        }

    def shutdown(self) -> None:
        """Kills isolated Tor daemon on browser exit."""
        if self.tor_proc:
            try:
                if self.tor_proc.stdout:
                    self.tor_proc.stdout.close()
                self.tor_proc.terminate()
                self.tor_proc.wait(timeout=0.5)
            except Exception:
                pass
            self.tor_proc = None
