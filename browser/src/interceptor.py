"""
TuxBrowser - Privacy Shield & Request Interceptor
High-performance domain matching and request interceptor for ad/tracker/telemetry blocking.
"""

from urllib.parse import urlparse
from typing import Dict, Set, Optional, Callable
from PySide6.QtWebEngineCore import (
    QWebEngineUrlRequestInterceptor,
    QWebEngineUrlRequestInfo
)
from PySide6.QtCore import QObject, Signal


# Comprehensive baseline set of known tracking, analytics, ad networks, and cryptomining hostnames & patterns
DEFAULT_BLOCKLIST = {
    # Google Ads & Analytics & Telemetry
    "google-analytics.com", "ssl.google-analytics.com", "analytics.google.com",
    "googletagmanager.com", "googletagservices.com", "googleadservices.com",
    "doubleclick.net", "adservice.google.com", "pagead2.googlesyndication.com",
    "admob.com", "2mdn.net", "google-analytics.bi.com",
    
    # Meta / Facebook Trackers
    "connect.facebook.net", "pixel.facebook.com", "an.facebook.com",
    "graph.instagram.com",
    
    # Yandex & Mail.ru Metrika & Ads
    "mc.yandex.ru", "an.yandex.ru", "metrika.yandex.ru", "top-fwz1.mail.ru",
    "target.my.com", "ad.mail.ru",
    
    # Ad Networks & Content Recommendation
    "adnxs.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
    "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
    "popads.net", "popcash.net", "adroll.com", "adcolony.com", "applovin.com",
    "adtechus.com", "smartadserver.com", "scorecardresearch.com", "quantserve.com",
    "yieldmo.com", "tribalfusion.com", "media.net", "revcontent.com",
    "sharethrough.com", "infolinks.com", "chitika.com", "adblade.com",
    
    # Trackers & Fingerprinting & Telemetry
    "hotjar.com", "mouseflow.com", "crazyegg.com", "segment.io", "segment.com",
    "mixpanel.com", "amplitude.com", "fullstory.com", "branch.io",
    "adjust.com", "appsflyer.com", "singular.net", "onesignal.com",
    "sentry.io", "bugsnag.com", "newrelic.com", "nr-data.net",
    
    # Crypto Mining in browser
    "coin-hive.com", "coinhive.com", "crypto-loot.com", "minr.pw", "coin-have.com",
    "webminepool.com", "monerominer.rocks", "jsecoin.com"
}

TRACKER_KEYWORDS = {
    "/ads/", "/ad/", "/advert/", "/telemetry/", "/analytics.js", "/gtm.js",
    "/pixel.", "/beacon.", "/track/", "/tracker.", "/stats.js", "/collect?",
    "pixel.gif", "beacon.gif"
}


TRACKING_QUERY_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "gbraid", "wbraid",
    "fbclid", "igshid",
    "mc_eid", "yclid", "ymclid",
    "_ga", "_gl",
    "dclid", "msclkid",
    "zanpid", "origin", "ref_", "si"
}


import re

URL_SCHEMES = ("http://", "https://", "tux://", "file://", "ftp://", "about:", "data:")

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/.*)?$"
)
IP_REGEX = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/.*)?$"
)
LOCALHOST_REGEX = re.compile(
    r"^localhost(?::\d+)?(?:/.*)?$", re.IGNORECASE
)


def is_direct_url(text: str) -> bool:
    """Returns True if the text represents a URL or domain rather than a search query."""
    if not text:
        return False
    s = text.strip()
    for scheme in URL_SCHEMES:
        if s.startswith(scheme):
            return True
    if " " in s or "\n" in s or "\t" in s:
        return False
    return bool(DOMAIN_REGEX.match(s) or IP_REGEX.match(s) or LOCALHOST_REGEX.match(s))


def resolve_input_to_url(text: str, default_search_template: str = "tux://search?q={query}") -> str:
    """Converts user input into a full valid URL or search query URL."""
    from urllib.parse import quote_plus
    s = text.strip()
    if not s:
        return "tux://home"
    if is_direct_url(s):
        for scheme in URL_SCHEMES:
            if s.startswith(scheme):
                return s
        if s.lower().startswith("localhost"):
            return f"http://{s}"
        return f"https://{s}"
    return default_search_template.replace("{query}", quote_plus(s))


def strip_tracking_parameters(url_str: str) -> str:
    """Removes known tracking query parameters (UTM, gclid, fbclid, etc.) from URLs."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    if not url_str or "?" not in url_str:
        return url_str
    try:
        parsed = urlparse(url_str)
        if not parsed.query:
            return url_str
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        cleaned_query = {
            k: v for k, v in query_dict.items()
            if k.lower() not in TRACKING_QUERY_PARAMS and not k.lower().startswith("utm_")
        }
        new_query = urlencode(cleaned_query, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return url_str


AUTH_SERVICES_WHITELIST = {
    "accounts.google.com", "gemini.google.com", "myaccount.google.com",
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "github.com", "login.microsoftonline.com", "passport.yandex.ru",
    "auth0.com", "appleid.apple.com"
}


class TuxRequestInterceptor(QWebEngineUrlRequestInterceptor):
    """Intercepts network requests to block ads, trackers, malicious domains, and prevent leaks."""

    def __init__(self, storage, ghost_manager=None, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.storage = storage
        self.ghost_manager = ghost_manager
        self.blocklist: Set[str] = set(DEFAULT_BLOCKLIST)
        self._load_custom_rules()
        
        # Mapping of (first_party_domain) -> count of blocked requests in current session
        self.page_blocked_counts: Dict[str, int] = {}
        self.on_blocked_callback: Optional[Callable[[str, str, int], None]] = None

    def _load_custom_rules(self):
        settings = self.storage.get_settings()
        custom = self.storage.get_shield_stats().get("custom_blocklist", [])
        for domain in custom:
            self.blocklist.add(domain.lower().strip())

    def _get_domain(self, url_str: str) -> str:
        try:
            parsed = urlparse(url_str)
            netloc = parsed.netloc.split(":")[0].lower()
            return netloc
        except Exception:
            return ""

    def is_blocked(self, request_url_str: str, first_party_domain: str) -> bool:
        # Check if first party domain is whitelisted by user
        if first_party_domain and self.storage.is_domain_whitelisted(first_party_domain):
            return False

        req_domain = self._get_domain(request_url_str)
        if not req_domain:
            return False

        # Don't block internal tux:// or qrc:/ URLs
        if request_url_str.startswith("tux://") or request_url_str.startswith("qrc:/"):
            return False

        # Protect essential authentication endpoints
        if req_domain in AUTH_SERVICES_WHITELIST:
            return False

        # 1. Exact match or subdomain match against blocklist
        parts = req_domain.split(".")
        for i in range(len(parts) - 1):
            sub = ".".join(parts[i:])
            if sub in self.blocklist:
                return True

        # 2. Check for tracker keywords in 3rd-party URL paths
        if req_domain != first_party_domain and self.storage.get_setting("block_trackers", True):
            lower_url = request_url_str.lower()
            for kw in TRACKER_KEYWORDS:
                if kw in lower_url:
                    return True

        return False

    def interceptRequest(self, info: QWebEngineUrlRequestInfo) -> None:
        url = info.requestUrl().toString()
        first_party_url = info.firstPartyUrl().toString()
        first_party_domain = self._get_domain(first_party_url)

        # 1. Network Kill-Switch: if Ghost Mode is active but tunnel is dropped, fail-closed
        if self.ghost_manager and self.storage.get_setting("kill_switch_enabled", True):
            target_mode = self.storage.get_setting("ghost_mode_type", "direct")
            if target_mode in ("tor", "custom") and not self.ghost_manager.is_ghost_active:
                if not (url.startswith("tux://") or url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
                    # Block unencrypted leak
                    info.block(True)
                    return

        # 2. Privacy Headers (DNT & GPC)
        if self.storage.get_setting("do_not_track", True):
            info.setHttpHeader(b"DNT", b"1")
            info.setHttpHeader(b"Sec-GPC", b"1")

        # 3. Locale & Language Masking aligned with active GeoIP
        if self.storage.get_setting("spoof_timezone", True):
            active_lang = self.storage.get_setting("active_language", "en-US")
            short_lang = active_lang.split("-")[0]
            if short_lang == "en":
                header_val = "en-US,en;q=0.9"
            else:
                header_val = f"{active_lang},{short_lang};q=0.9,en-US;q=0.8,en;q=0.7"
            info.setHttpHeader(b"Accept-Language", header_val.encode("utf-8"))

        # 4. Referrer Leak Protection on 3rd-party requests
        req_domain = self._get_domain(url)
        if first_party_domain and req_domain and req_domain != first_party_domain:
            info.setHttpHeader(b"Referer", b"")

        # 5. IPv6 Leak Shield: block raw unproxied direct IPv6 requests & dual-stack IPv6 probes
        if self.storage.get_setting("block_ipv6_leaks", True):
            req_host = info.requestUrl().host().lower()
            if req_host.startswith("[") or (":" in req_host and not req_host.startswith("127.") and req_host != "localhost") or "ipv6." in req_host or req_host.startswith("ipv6."):
                info.block(True)
                return

        # 6. Ad & Tracker Blocking
        block_trackers = self.storage.get_setting("block_trackers", True)
        block_ads = self.storage.get_setting("block_ads", True)

        if (block_trackers or block_ads) and self.is_blocked(url, first_party_domain):
            info.block(True)
            self.storage.increment_stat("total_trackers_blocked", 1)
            
            if first_party_domain:
                self.page_blocked_counts[first_party_domain] = self.page_blocked_counts.get(first_party_domain, 0) + 1
                curr_count = self.page_blocked_counts[first_party_domain]
            else:
                curr_count = 1

            if self.on_blocked_callback:
                self.on_blocked_callback(first_party_domain, url, curr_count)
            return

    def get_blocked_count(self, domain: str) -> int:
        return self.page_blocked_counts.get(domain.lower(), 0)

    def reset_page_count(self, domain: str) -> None:
        if domain.lower() in self.page_blocked_counts:
            self.page_blocked_counts[domain.lower()] = 0
