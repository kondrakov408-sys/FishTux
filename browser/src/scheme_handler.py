"""
TuxBrowser - Custom Scheme Handler (tux://)
Serves internal pages: tux://home, tux://settings, tux://history, tux://bookmarks, tux://shield, tux://about, and assets.
"""

import json
import os
import time
from urllib.parse import parse_qs, urlparse
from PySide6.QtWebEngineCore import (
    QWebEngineUrlSchemeHandler,
    QWebEngineUrlRequestJob
)
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QUrl


class TuxSchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, storage, assets_dir: str, parent=None, ghost_manager=None):
        super().__init__(parent)
        self.storage = storage
        self.assets_dir = assets_dir
        self.ghost_manager = ghost_manager

    def _render_page(self, page_name: str, replacements: dict = None) -> bytes:
        file_path = os.path.join(self.assets_dir, "pages", f"{page_name}.html")
        if not os.path.exists(file_path):
            return f"<h1>404 Tux Page Not Found: {page_name}</h1>".encode("utf-8")
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if replacements:
            for k, v in replacements.items():
                content = content.replace(f"{{{{{k}}}}}", str(v))

        return content.encode("utf-8")

    def _render_history(self) -> bytes:
        history = self.storage.get_history(limit=200)
        if not history:
            items_html = '<div class="empty-state">История посещений пуста 🐧</div>'
        else:
            items = []
            for h in history:
                title = h.get("title") or h.get("url")
                url = h.get("url", "")
                ts = h.get("timestamp", 0)
                time_str = time.strftime("%d.%m %H:%M", time.localtime(ts)) if ts else ""
                count = h.get("visit_count", 1)
                
                item = f"""
                <div class="history-item">
                  <a href="{url}" class="item-main">
                    <span class="item-title">{title}</span>
                    <span class="item-url">{url}</span>
                  </a>
                  <div class="item-meta">
                    <span>{time_str}</span>
                    <span>({count} визитов)</span>
                    <button class="del-btn" title="Удалить" onclick="deleteItem('{url}')">✖</button>
                  </div>
                </div>
                """
                items.append(item)
            items_html = "\n".join(items)

        return self._render_page("history", {"HISTORY_ITEMS": items_html})

    def _render_bookmarks(self) -> bytes:
        bookmarks = self.storage.get_bookmarks()
        if not bookmarks:
            items_html = '<div class="empty-state">Нет сохраненных закладок 🐧</div>'
        else:
            items = []
            for b in bookmarks:
                title = b.get("title", "")
                url = b.get("url", "")
                cat = b.get("category", "General")
                
                item = f"""
                <div class="card">
                  <a href="{url}" class="card-link">
                    <div class="card-title">⭐ {title}</div>
                    <div class="card-url">{url}</div>
                  </a>
                  <div class="card-footer">
                    <span class="card-category">{cat}</span>
                    <button class="del-btn" title="Удалить" onclick="deleteBookmark('{url}')">Удалить</button>
                  </div>
                </div>
                """
                items.append(item)
            items_html = "\n".join(items)

        return self._render_page("bookmarks", {"BOOKMARK_ITEMS": items_html})

    def _render_shield(self) -> bytes:
        stats = self.storage.get_shield_stats()
        trackers = stats.get("total_trackers_blocked", 0)
        https_count = stats.get("total_https_upgrades", 0)
        whitelist = stats.get("domains_whitelist", [])
        
        if not whitelist:
            wl_html = '<span style="color:#64748b;font-size:0.85rem;">Список пуст (все сайты фильтруются)</span>'
        else:
            wl_html = "".join([f'<span class="tag">🌐 {d}</span>' for d in whitelist])

        return self._render_page("shield", {
            "TOTAL_TRACKERS": trackers,
            "HTTPS_UPGRADES": https_count,
            "WHITELIST_TAGS": wl_html
        })

    def _render_settings(self) -> bytes:
        import json
        import html as html_lib
        s = self.storage.get_settings()
        if self.ghost_manager:
            s["ghost_status"] = self.ghost_manager.get_status()
        settings_json = json.dumps(s, ensure_ascii=False)

        ghost_mode = s.get("ghost_mode_type", "tor")
        sec_level = s.get("security_level", "standard")
        engine = s.get("search_engine", "TuxFind")

        has_wt = bool(self.ghost_manager and self.ghost_manager._find_transport_binary("webtunnel"))
        has_obfs = bool(self.ghost_manager and self.ghost_manager._find_transport_binary("obfs4"))
        wt_badge = '<span style="color:#10b981;">⚡ WebTunnel: ✓ Готов</span>' if has_wt else '<span style="color:#f59e0b;">⚡ WebTunnel: ⚠️ webtunnel-client не найден</span>'
        obfs_badge = '<span style="color:#10b981;">🛡️ obfs4: ✓ Готов</span>' if has_obfs else '<span style="color:#f59e0b;">🛡️ obfs4: ⚠️ obfs4proxy не найден</span>'

        replacements = {
            "SETTINGS_JSON": settings_json,
            "CHECKED_KILL_SWITCH": "checked" if s.get("kill_switch_enabled", True) else "",
            "CHECKED_BLOCK_TRACKERS": "checked" if s.get("block_trackers", True) else "",
            "CHECKED_BLOCK_ADS": "checked" if s.get("block_ads", True) else "",
            "CHECKED_HTTPS_ONLY": "checked" if s.get("https_only", True) else "",
            "CHECKED_BLOCK_THIRD_PARTY_COOKIES": "checked" if s.get("block_third_party_cookies", True) else "",
            "CHECKED_WEBRTC_LEAK_PROTECTION": "checked" if s.get("webrtc_leak_protection", True) else "",
            "CHECKED_BLOCK_IPV6_LEAKS": "checked" if s.get("block_ipv6_leaks", True) else "",
            "CHECKED_PRIVACY_SOUND_ALERTS": "checked" if s.get("privacy_sound_alerts", True) else "",
            "CHECKED_BLOCK_HARDWARE_SENSORS": "checked" if s.get("block_hardware_sensors", True) else "",
            "CHECKED_ANTI_FINGERPRINTING": "checked" if s.get("anti_fingerprinting", True) else "",
            "CHECKED_STRIP_TRACKING_URLS": "checked" if s.get("strip_tracking_urls", True) else "",
            "CHECKED_SPOOF_TIMEZONE": "checked" if s.get("spoof_timezone", True) else "",
            "CHECKED_DO_NOT_TRACK": "checked" if s.get("do_not_track", True) else "",
            "CHECKED_CLEAR_HISTORY_ON_EXIT": "checked" if s.get("clear_history_on_exit", False) else "",
            "CHECKED_CLEAR_CACHE_ON_EXIT": "checked" if s.get("clear_cache_on_exit", False) else "",
            
            "SELECTED_GHOST_DIRECT": "selected" if ghost_mode == "direct" else "",
            "SELECTED_GHOST_TOR": "selected" if ghost_mode == "tor" else "",
            "SELECTED_GHOST_CUSTOM": "selected" if ghost_mode == "custom" else "",
            "DISPLAY_CUSTOM_PROXY": "flex" if ghost_mode == "custom" else "none",
            "DISPLAY_TOR_BRIDGES": "flex" if ghost_mode == "tor" else "none",
            "GHOST_CUSTOM_PROXY_VALUE": html_lib.escape(str(s.get("ghost_custom_proxy", ""))),
            "TOR_BRIDGES_VALUE": html_lib.escape(str(s.get("tor_bridges", ""))),
            "WEBTUNNEL_BADGE": wt_badge,
            "OBFS4_BADGE": obfs_badge,

            "SELECTED_SEC_STANDARD": "selected" if sec_level == "standard" else "",
            "SELECTED_SEC_SAFER": "selected" if sec_level == "safer" else "",
            "SELECTED_SEC_SAFEST": "selected" if sec_level == "safest" else "",

            "SELECTED_ENG_TUX": "selected" if engine == "TuxFind" else "",
            "SELECTED_ENG_DDG": "selected" if engine == "DuckDuckGo" else "",
            "SELECTED_ENG_BRAVE": "selected" if engine == "Brave" else "",
            "SELECTED_ENG_SEARX": "selected" if engine == "SearXNG" else "",
            "SELECTED_ENG_STARTPAGE": "selected" if engine == "Startpage" else "",
            "HOME_PAGE_VALUE": html_lib.escape(str(s.get("home_page", "tux://home")))
        }
        return self._render_page("settings", replacements)

    def _render_search(self, query: str, category: str = "all", safe: str = "strict", time_filter: str = "all") -> bytes:
        import html as html_lib
        import json
        from urllib.request import Request, ProxyHandler, build_opener
        from urllib.parse import quote_plus

        query_clean = query.strip()
        cat_clean = category.strip().lower() if category else "all"
        safe_clean = safe.strip().lower() if safe else "strict"
        time_clean = time_filter.strip().lower() if time_filter else "all"

        from browser.src.interceptor import is_direct_url, resolve_input_to_url

        if not query_clean:
            return self._render_page("search", {
                "QUERY": "",
                "QUERY_ENCODED": "",
                "CATEGORY": cat_clean,
                "CAT_ALL_ACTIVE": "active" if cat_clean == "all" else "",
                "CAT_IMAGES_ACTIVE": "active" if cat_clean == "images" else "",
                "CAT_VIDEOS_ACTIVE": "active" if cat_clean in ("videos", "video") else "",
                "CAT_CODE_ACTIVE": "active" if cat_clean == "code" else "",
                "CAT_WIKI_ACTIVE": "active" if cat_clean == "wiki" else "",
                "INSTANT_ANSWER_HTML": "",
                "RESULTS_HTML": '<div class="empty-state"><div style="font-size:2.5rem;margin-bottom:10px;">🔍</div><div>Введите поисковый запрос выше</div></div>',
                "RELATED_SEARCHES_HTML": "",
                "TOOK_TEXT": ""
            })

        if is_direct_url(query_clean) and cat_clean == "all":
            direct_url = resolve_input_to_url(query_clean)
            redirect_html = f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Переход...</title></head><body><script>window.location.href = "{html_lib.escape(direct_url)}";</script></body></html>'
            return redirect_html.encode("utf-8")

        api_url = f"http://127.0.0.1:8080/api/v1/search?q={quote_plus(query_clean)}&category={quote_plus(cat_clean)}&safe={quote_plus(safe_clean)}&time={quote_plus(time_clean)}"
        data = None
        try:
            req = Request(api_url, headers={"User-Agent": "TuxBrowser/2.0"})
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            with opener.open(req, timeout=3.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"[TuxSchemeHandler] TuxFind backend request failed: {e}")

        instant_html = ""
        related_html = ""
        if not data or "results" not in data:
            results_html = f'''
            <div class="error-state">
              <div style="font-size:2.5rem;margin-bottom:10px;">⚠️</div>
              <h3 style="color:#f59e0b;margin-bottom:8px;">Сервис TuxFind недоступен на localhost:8080</h3>
              <p style="color:var(--text-muted);font-size:0.9rem;max-width:500px;margin:0 auto 16px;">
                Поисковый движок поднимается автоматически.<br>
                Если он выключен, запустите его:<br>
                <code style="background:#0d1117;padding:4px 8px;border-radius:4px;color:#38bdf8;display:inline-block;margin-top:6px;">cd TuxFind && ./tuxfind</code>
              </p>
              <a href="https://duckduckgo.com/?q={quote_plus(query_clean)}" class="btn-fallback">Искать через DuckDuckGo 🦆</a>
            </div>
            '''
            took_text = ""
        else:
            # 1. Render Instant Answer Card if present
            instant_ans = data.get("instant_answer")
            if instant_ans and isinstance(instant_ans, dict):
                ans_type = instant_ans.get("type", "knowledge")
                ans_title = html_lib.escape(instant_ans.get("title", ""))
                ans_desc = html_lib.escape(instant_ans.get("description", ""))
                ans_body = html_lib.escape(instant_ans.get("answer", ""))
                ans_src = html_lib.escape(instant_ans.get("source", "Wikipedia (RU)"))
                ans_img = instant_ans.get("image_url", "")
                ans_url = instant_ans.get("source_url", "")

                if ans_type == "calc":
                    instant_html = f'''
                    <div class="instant-box calc-box">
                      <div class="instant-header">
                        <span class="instant-badge">🧮 Калькулятор</span>
                        <span class="instant-src">{ans_src}</span>
                      </div>
                      <div class="calc-expression">{ans_desc}</div>
                      <div class="calc-result">= {ans_body}</div>
                    </div>
                    '''
                elif ans_type == "linux_cmd":
                    instant_html = f'''
                    <div class="instant-box linux-box">
                      <div class="instant-header">
                        <span class="instant-badge">🐧 Linux Справочник</span>
                        <span class="instant-src">{ans_src}</span>
                      </div>
                      <h2 class="instant-title">{ans_title}</h2>
                      <div class="instant-desc">{ans_desc}</div>
                      <pre class="instant-code"><code>{ans_body}</code></pre>
                    </div>
                    '''
                else:
                    img_tag = f'<div class="instant-img-col"><img src="{html_lib.escape(ans_img)}" class="instant-thumb" alt="{ans_title}"></div>' if ans_img else ''
                    link_href = html_lib.escape(ans_url) if ans_url else "#"
                    instant_html = f'''
                    <div class="instant-box knowledge-box">
                      <div class="knowledge-main-row">
                        <div class="knowledge-content">
                          <h2 class="instant-title">{ans_title}</h2>
                          <div class="instant-extract">
                            {ans_body}
                            <a href="{link_href}" class="instant-more-link" target="_blank">Продолжение: {ans_src}</a>
                          </div>
                        </div>
                        {img_tag}
                      </div>
                      <div class="instant-footer">
                        <span>Источник: <a href="{link_href}" target="_blank" class="footer-link">{ans_src}</a> • Эта информация вам пригодилась? <span class="feedback-btn">👍</span> <span class="feedback-btn">👎</span></span>
                      </div>
                    </div>
                    '''

            # 2. Render Results List
            results = data.get("results")
            if not isinstance(results, list):
                results = []
            took_ms = data.get("took_ms", 0)
            took_text = f"⚡ Найдено: {len(results)} за {took_ms} мс • TuxFind Engine 2.0"

            if not results:
                results_html = f'''
                <div class="empty-state">
                  <div style="font-size:2.5rem;margin-bottom:10px;">🐧❓</div>
                  <div style="font-size:1.1rem;margin-bottom:6px;">По запросу ничего не найдено</div>
                  <p style="color:var(--text-muted);font-size:0.9rem;">Попробуйте изменить формулировку или проверьте написание</p>
                  <a href="https://duckduckgo.com/?q={quote_plus(query_clean)}" class="btn-fallback">Искать в DuckDuckGo 🦆</a>
                </div>
                '''
            else:
                cards = []
                if cat_clean == "images":
                    for item in results:
                        title_esc = html_lib.escape(item.get("title", ""))
                        url_esc = html_lib.escape(item.get("url", ""))
                        thumb_esc = html_lib.escape(item.get("thumbnail_url") or item.get("media_url") or "")
                        site_name = html_lib.escape(item.get("site_name", ""))
                        dim_esc = html_lib.escape(item.get("snippet", ""))

                        card = f'''
                        <a href="{url_esc}" target="_blank" class="image-card">
                          <div class="image-thumb-wrap">
                            <img src="{thumb_esc}" alt="{title_esc}" loading="lazy" onerror="this.src='tux://assets/icons/tux.svg'">
                          </div>
                          <div class="image-meta">
                            <div class="image-title">{title_esc}</div>
                            <div class="image-domain">
                              <span>{site_name}</span>
                              <span>{dim_esc}</span>
                            </div>
                          </div>
                        </a>
                        '''
                        cards.append(card)
                    results_html = '<div class="image-grid">' + "\n".join(cards) + '</div>'
                elif cat_clean == "videos":
                    for item in results:
                        title_esc = html_lib.escape(item.get("title", ""))
                        url_esc = html_lib.escape(item.get("url", ""))
                        thumb_esc = html_lib.escape(item.get("thumbnail_url") or "")
                        pub_esc = html_lib.escape(item.get("publisher") or item.get("site_name") or "Видео")
                        dur_esc = html_lib.escape(item.get("duration", ""))
                        dur_tag = f'<span class="video-duration">{dur_esc}</span>' if dur_esc else ""

                        card = f'''
                        <a href="{url_esc}" target="_blank" class="video-card">
                          <div class="video-thumb-wrap">
                            <img src="{thumb_esc}" alt="{title_esc}" loading="lazy" onerror="this.src='tux://assets/icons/tux.svg'">
                            <div class="video-play-badge">▶</div>
                            {dur_tag}
                          </div>
                          <div class="video-meta">
                            <div class="video-title">{title_esc}</div>
                            <div class="video-channel">📺 {pub_esc}</div>
                          </div>
                        </a>
                        '''
                        cards.append(card)
                    results_html = '<div class="video-grid">' + "\n".join(cards) + '</div>'
                else:
                    for item in results:
                        title_esc = html_lib.escape(item.get("title", ""))
                        url_esc = html_lib.escape(item.get("url", ""))
                        snippet_esc = html_lib.escape(item.get("snippet", ""))
                        site_name = html_lib.escape(item.get("site_name", ""))

                        try:
                            parsed_url = urlparse(item.get("url", ""))
                            host = parsed_url.netloc
                            path_parts = [p for p in parsed_url.path.split("/") if p]
                            if path_parts:
                                breadcrumb = f"https://{host} › " + " › ".join(path_parts[:2])
                            else:
                                breadcrumb = f"https://{host}"
                        except Exception:
                            host = url_esc
                            breadcrumb = url_esc

                        if not site_name:
                            site_name = host.replace("www.", "").capitalize()

                        first_char = site_name[0].upper() if site_name else "W"

                        card = f'''
                        <div class="result-item">
                          <div class="result-site-row">
                            <div class="site-icon-circle">{first_char}</div>
                            <div class="site-meta">
                              <span class="site-name">{site_name}</span>
                              <span class="site-breadcrumb">{html_lib.escape(breadcrumb)}</span>
                            </div>
                            <span class="result-more-btn">•••</span>
                          </div>
                          <a href="{url_esc}" class="result-title">{title_esc}</a>
                          <div class="result-snippet">{snippet_esc}</div>
                        </div>
                        '''
                        cards.append(card)
                    results_html = '<div class="results-list">' + "\n".join(cards) + '</div>'

            # 3. Render Related Searches for Sidebar
            related_searches = data.get("related_searches", [])
            if not related_searches:
                related_searches = [
                    f"{query_clean} википедия",
                    f"{query_clean} скачать",
                    f"{query_clean} официальный сайт",
                    f"{query_clean} linux",
                    f"{query_clean} онлайн"
                ]

            related_pills = []
            for term in related_searches:
                term_esc = html_lib.escape(term)
                pill = f'''
                <a href="tux://search?q={quote_plus(term)}" class="related-pill">
                  <span class="related-icon">🔍</span>
                  <span class="related-text">{term_esc}</span>
                </a>
                '''
                related_pills.append(pill)
            related_html = "\n".join(related_pills)

        return self._render_page("search", {
            "QUERY": html_lib.escape(query_clean),
            "QUERY_ENCODED": quote_plus(query_clean),
            "CATEGORY": cat_clean,
            "CAT_ALL_ACTIVE": "active" if cat_clean == "all" else "",
            "CAT_IMAGES_ACTIVE": "active" if cat_clean == "images" else "",
            "CAT_VIDEOS_ACTIVE": "active" if cat_clean in ("videos", "video") else "",
            "CAT_CODE_ACTIVE": "active" if cat_clean == "code" else "",
            "CAT_WIKI_ACTIVE": "active" if cat_clean == "wiki" else "",
            "INSTANT_ANSWER_HTML": instant_html,
            "RESULTS_HTML": results_html,
            "RELATED_SEARCHES_HTML": related_html,
            "TOOK_TEXT": took_text
        })

    def requestStarted(self, job: QWebEngineUrlRequestJob) -> None:
        try:
            req_url = job.requestUrl().toString()
            parsed = urlparse(req_url)
            path = parsed.path.strip("/")
            host = parsed.netloc.lower()

            # Route matching: tux://home, tux://settings, etc.
            route = host if host else path
            if not route:
                route = "home"

            # Handle Action URLs: tux://action?type=...
            if route == "action":
                query = parse_qs(parsed.query)
                action_type = query.get("type", [""])[0]
                if action_type == "delete_history":
                    target_url = query.get("url", [""])[0]
                    if target_url:
                        self.storage.delete_history_item(target_url)
                    redirect_html = '<script>window.location.href="tux://history";</script>'
                    self._reply_bytes(job, redirect_html.encode("utf-8"), "text/html")
                    return
                elif action_type == "clear_history":
                    self.storage.clear_history()
                    redirect_html = '<script>window.location.href="tux://history";</script>'
                    self._reply_bytes(job, redirect_html.encode("utf-8"), "text/html")
                    return
                elif action_type == "delete_bookmark":
                    target_url = query.get("url", [""])[0]
                    if target_url:
                        self.storage.remove_bookmark(target_url)
                    redirect_html = '<script>window.location.href="tux://bookmarks";</script>'
                    self._reply_bytes(job, redirect_html.encode("utf-8"), "text/html")
                    return
                elif action_type == "clear_data":
                    self.storage.clear_history()
                    redirect_html = '<script>alert("Данные успешно очищены!"); window.location.href="tux://settings";</script>'
                    self._reply_bytes(job, redirect_html.encode("utf-8"), "text/html")
                    return
                elif action_type == "save_setting":
                    key = query.get("key", [""])[0]
                    val_str = query.get("value", [""])[0]
                    val = val_str
                    if key:
                        try:
                            val = json.loads(val_str)
                        except Exception:
                            val = val_str
                        self.storage.set_setting(key, val)
                        if key == "ghost_mode_type" and self.ghost_manager:
                            if val == "direct":
                                self.ghost_manager.disable_ghost_mode()
                            elif val == "custom":
                                custom_proxy = self.storage.get_setting("ghost_custom_proxy", "")
                                self.ghost_manager.enable_ghost_mode("custom", custom_proxy)
                            elif val == "tor":
                                if not (self.ghost_manager.is_ghost_active and self.ghost_manager.current_mode == "tor"):
                                    self.ghost_manager.enable_ghost_mode("tor")
                        elif key == "ghost_custom_proxy" and self.ghost_manager:
                            self.ghost_manager.custom_proxy_str = str(val)
                            if self.ghost_manager.is_ghost_active and self.ghost_manager.current_mode == "custom":
                                self.ghost_manager.enable_ghost_mode("custom", str(val))
                        elif key == "tor_bridges" and self.ghost_manager:
                            old_bridges = self.ghost_manager.tor_bridges
                            self.ghost_manager.tor_bridges = str(val)
                            if str(val) != old_bridges and self.ghost_manager.is_ghost_active and self.ghost_manager.current_mode == "tor":
                                self.ghost_manager.enable_ghost_mode("tor")
                    resp = json.dumps({"status": "ok", "key": key, "value": val})
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "save_all_settings":
                    payload_str = query.get("payload", [""])[0]
                    if payload_str:
                        try:
                            updates = json.loads(payload_str)
                            if isinstance(updates, dict):
                                old_mode = self.storage.get_setting("ghost_mode_type", "tor")
                                old_bridges = self.storage.get_setting("tor_bridges", "")
                                old_proxy = self.storage.get_setting("ghost_custom_proxy", "")

                                self.storage.update_settings(updates)

                                if self.ghost_manager:
                                    new_mode = updates.get("ghost_mode_type", old_mode)
                                    new_proxy = updates.get("ghost_custom_proxy", old_proxy)
                                    new_bridges = str(updates.get("tor_bridges", old_bridges))
                                    self.ghost_manager.tor_bridges = new_bridges

                                    mode_changed = (new_mode != old_mode) or (not self.ghost_manager.is_ghost_active and new_mode != "direct")
                                    bridges_changed = (new_bridges != old_bridges)
                                    proxy_changed = (new_proxy != old_proxy)

                                    if new_mode == "direct":
                                        if self.ghost_manager.is_ghost_active:
                                            self.ghost_manager.disable_ghost_mode()
                                    elif new_mode == "custom":
                                        if mode_changed or proxy_changed or not self.ghost_manager.is_ghost_active:
                                            self.ghost_manager.enable_ghost_mode("custom", new_proxy)
                                    elif new_mode == "tor":
                                        if mode_changed or (bridges_changed and self.ghost_manager.is_ghost_active) or not self.ghost_manager.is_ghost_active:
                                            self.ghost_manager.enable_ghost_mode("tor")
                        except Exception as e:
                            print(f"[TuxSchemeHandler] Save all settings error: {e}")
                    resp = json.dumps({"status": "ok"})
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "get_ghost_status":
                    if self.ghost_manager:
                        st = self.ghost_manager.get_status()
                    else:
                        st = {"is_active": False, "mode": "direct", "ip": "Недоступно", "country": "..."}
                    resp = json.dumps(st)
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "get_settings":
                    settings = self.storage.get_settings()
                    if self.ghost_manager:
                        settings["ghost_status"] = self.ghost_manager.get_status()
                    resp = json.dumps(settings)
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "export_profile":
                    profile_dict = self.storage.export_profile_dict()
                    resp = json.dumps(profile_dict, ensure_ascii=False, indent=2)
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "import_profile":
                    payload = query.get("payload", [""])[0]
                    ok = False
                    if payload:
                        try:
                            data = json.loads(payload)
                            ok = self.storage.import_profile_dict(data)
                        except Exception as e:
                            print(f"[TuxSchemeHandler] Import error: {e}")
                    resp = json.dumps({"status": "ok" if ok else "error"})
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return
                elif action_type == "reset_profile":
                    self.storage.reset_to_defaults()
                    resp = json.dumps({"status": "ok"})
                    self._reply_bytes(job, resp.encode("utf-8"), "application/json")
                    return

            # Assets routing: tux://assets/icons/...
            if route == "assets" or parsed.netloc == "assets":
                subpath = parsed.path.lstrip("/")
                full_asset_path = os.path.join(self.assets_dir, subpath)
                if os.path.exists(full_asset_path):
                    content_type = "image/svg+xml" if full_asset_path.endswith(".svg") else "application/octet-stream"
                    with open(full_asset_path, "rb") as f:
                        data = f.read()
                    self._reply_bytes(job, data, content_type)
                    return
                else:
                    job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
                    return

            # Privacy Image Proxy: tux://image-proxy?url=...
            if route == "image-proxy":
                query_dict = parse_qs(parsed.query)
                target_url = query_dict.get("url", [""])[0]
                if target_url:
                    # Redirect directly to high-performance Go proxy
                    from urllib.parse import quote_plus
                    proxy_redirect = f"http://127.0.0.1:8080/api/v1/image-proxy?url={quote_plus(target_url)}"
                    job.redirect(QUrl(proxy_redirect))
                    return
                else:
                    job.fail(QWebEngineUrlRequestJob.Error.UrlInvalid)
                    return

            # Render Pages
            if route in ("home", "newtab", "start"):
                content = self._render_page("home")
                self._reply_bytes(job, content, "text/html")
            elif route == "search":
                query_dict = parse_qs(parsed.query)
                q = query_dict.get("q", [""])[0]
                cat = query_dict.get("category", ["all"])[0]
                safe = query_dict.get("safe", ["strict"])[0]
                t_filter = query_dict.get("time", ["all"])[0]
                content = self._render_search(q, cat, safe, t_filter)
                self._reply_bytes(job, content, "text/html")
            elif route == "settings":
                content = self._render_settings()
                self._reply_bytes(job, content, "text/html")
            elif route == "history":
                content = self._render_history()
                self._reply_bytes(job, content, "text/html")
            elif route == "bookmarks":
                content = self._render_bookmarks()
                self._reply_bytes(job, content, "text/html")
            elif route in ("shield", "privacybadger", "badger"):
                content = self._render_shield()
                self._reply_bytes(job, content, "text/html")
            elif route == "about":
                content = self._render_page("about")
                self._reply_bytes(job, content, "text/html")
            else:
                job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        except Exception as e:
            print(f"[TuxSchemeHandler] Error in requestStarted: {e}")
            try:
                job.fail(QWebEngineUrlRequestJob.Error.RequestFailed)
            except Exception:
                pass

    def _reply_bytes(self, job: QWebEngineUrlRequestJob, data: bytes, mime_type: str) -> None:
        buf = QBuffer(job)
        buf.setData(QByteArray(data))
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        job.reply(mime_type.encode("utf-8"), buf)
