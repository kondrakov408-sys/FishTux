"""
TuxBrowser - Tab View Component
Wraps QWebEngineView with tab state, SSL inspection, zoom controls, and custom context menus.
"""

from urllib.parse import urlparse
from typing import Optional

from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import (
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineSettings
)
from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import QMenu


class TuxWebEnginePage(QWebEnginePage):
    """Custom page to handle certificate errors, hardware blocking, and window creation."""

    def __init__(self, profile: QWebEngineProfile, parent=None):
        super().__init__(profile, parent)
        self.featurePermissionRequested.connect(self._on_feature_permission_requested)

    def _on_feature_permission_requested(self, securityOrigin: QUrl, feature: QWebEnginePage.Feature):
        # Strictly deny all invasive sensor, camera, mic, and hardware permissions
        self.setFeaturePermission(securityOrigin, feature, QWebEnginePage.PermissionPolicy.PermissionDeniedByUser)
        feat_name = str(feature).split(".")[-1]
        print(f"[TuxShield] Blocked hardware permission request: {feat_name} from {securityOrigin.toString()}")
        parent_view = self.parent()
        if parent_view and hasattr(parent_view, "privacy_alert"):
            origin_str = securityOrigin.host() or securityOrigin.toString()
            parent_view.privacy_alert.emit(f"Доступ к оборудованию ({feat_name})", origin_str)

    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        if "[TuxPrivacyAlert]" in message:
            parts = message.split("[TuxPrivacyAlert]", 1)
            reason = parts[1].strip() if len(parts) > 1 else message
            parent_view = self.parent()
            if parent_view and hasattr(parent_view, "privacy_alert"):
                parsed_source = sourceID
                if "://" in sourceID:
                    parsed_source = urlparse(sourceID).netloc or sourceID
                parent_view.privacy_alert.emit(reason, parsed_source)
        super().javaScriptConsoleMessage(level, message, lineNumber, sourceID)

    def certificateError(self, certificateError) -> bool:
        # Strict security: block invalid certificates by default
        print(f"[TuxBrowser Security] Certificate error for {certificateError.url().toString()}: {certificateError.errorDescription()}")
        return False

    def acceptNavigationRequest(self, url: QUrl, navType: QWebEnginePage.NavigationType, isMainFrame: bool) -> bool:
        # Guarantee all clicks on internal & external links, forms, and redirects are accepted without blockage
        return True

    def createWindow(self, windowType):
        # Support OAuth popups and link target="_blank" by adding a new tab
        parent_view = self.parent()
        if parent_view and hasattr(parent_view, "window"):
            main_win = parent_view.window()
            if hasattr(main_win, "add_new_tab"):
                new_tab = main_win.add_new_tab("about:blank")
                return new_tab.page()
        return super().createWindow(windowType)


class TuxTabView(QWebEngineView):
    """Encapsulates a single browser tab with its security context."""

    title_changed = Signal(str)
    url_changed = Signal(QUrl)
    icon_changed = Signal(QIcon)
    security_changed = Signal(str, str)  # status ('secure', 'insecure', 'internal'), details
    load_progress = Signal(int)
    blocked_count_changed = Signal(int)
    privacy_grade_changed = Signal(str, str, str)  # grade, color, description
    privacy_alert = Signal(str, str)  # reason, origin

    def __init__(self, profile: QWebEngineProfile, interceptor, storage, parent=None):
        super().__init__(parent)
        self.interceptor = interceptor
        self.storage = storage
        self.current_domain = ""
        self.is_internal_page = False
        self.security_status = "internal"

        # Custom Page
        self.custom_page = TuxWebEnginePage(profile, self)
        self.setPage(self.custom_page)

        # Apply WebEngine Settings
        self._apply_security_settings()

        # Connect signals
        self.titleChanged.connect(self._on_title_changed)
        self.urlChanged.connect(self._on_url_changed)
        self.iconChanged.connect(self.icon_changed.emit)
        self.loadProgress.connect(self.load_progress.emit)
        self.loadFinished.connect(self._on_load_finished)

    def _apply_security_settings(self):
        settings = self.settings()
        sec_level = self.storage.get_setting("security_level", "standard")

        # Javascript policy:
        # Internal tux:// pages MUST ALWAYS have Javascript enabled so UI, settings, search suggestions, etc. work!
        current_url_str = self.url().toString() if self.url() else ""
        is_internal = current_url_str.startswith("tux://") or not current_url_str
        js_enabled = is_internal or (sec_level != "safest")

        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, js_enabled)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, js_enabled)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

        # WebGL & Graphics policy (Safer & Safest disable WebGL on untrusted web pages)
        webgl_enabled = is_internal or (sec_level == "standard")
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, webgl_enabled)
        settings.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, True)

        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowWindowActivationFromJavaScript, js_enabled)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FocusOnNavigationEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, (sec_level != "standard") and not is_internal)

    def get_privacy_grade(self) -> tuple:
        """Calculates DuckDuckGo-style Privacy Grade (grade, color, description)."""
        count = self.interceptor.get_blocked_count(self.current_domain)
        ghost_mgr = getattr(self.interceptor, "ghost_manager", None)
        ghost_active = bool(ghost_mgr and ghost_mgr.is_ghost_active)

        if self.is_internal_page:
            return ("A+", "#10b981", "Внутренняя песочница Tux (100% Zero-Logs защита)")
        
        if ghost_active:
            if self.security_status == "secure":
                return ("A+", "#10b981", f"Анонимность Tux Ghost: Защита туннеля + HTTPS ({count} трекеров)")
            else:
                return ("B", "#f59e0b", f"Tux Ghost активен, но страница передается без HTTPS (HTTP)")

        if self.security_status == "secure":
            if count == 0:
                return ("A", "#10b981", "Надежный сайт: HTTPS TLS шифрование, трекеры не обнаружены")
            elif count <= 3:
                return ("B+", "#38bdf8", f"Щит активен: HTTPS + обезврежено {count} сторонних трекеров")
            else:
                return ("B", "#38bdf8", f"Высокая активность трекеров: {count} нейтрализовано Tux Shield")
        elif self.security_status == "insecure":
            if count == 0:
                return ("C", "#f59e0b", "Небезопасно: незашифрованный HTTP протокол")
            else:
                return ("D", "#ef4444", f"Опасно: незашифрованный HTTP + {count} трекеров")

        return ("B", "#38bdf8", "Стандартная защита Tux")

    def _on_title_changed(self, title: str):
        display_title = title if title else "Новая вкладка 🐧"
        self.title_changed.emit(display_title)

    def _on_url_changed(self, qurl: QUrl):
        url_str = qurl.toString()
        parsed = urlparse(url_str)
        self.current_domain = parsed.netloc.split(":")[0].lower()

        # Determine security level
        if url_str.startswith("tux://"):
            self.is_internal_page = True
            self.security_status = "internal"
            self.security_changed.emit("internal", "Внутренняя страница Tux")
        elif url_str.startswith("https://"):
            self.is_internal_page = False
            self.security_status = "secure"
            self.security_changed.emit("secure", f"Защищенное HTTPS соединение ({self.current_domain})")
        elif url_str.startswith("http://"):
            self.is_internal_page = False
            self.security_status = "insecure"
            self.security_changed.emit("insecure", f"Внимание: Незащищенное HTTP соединение ({self.current_domain})")
        else:
            self.security_status = "unknown"
            self.security_changed.emit("unknown", url_str)

        # Re-apply security settings dynamically based on internal vs external page
        self._apply_security_settings()

        # Notify URL change
        self.url_changed.emit(qurl)

        # Update blocked count & grade
        count = self.interceptor.get_blocked_count(self.current_domain)
        self.blocked_count_changed.emit(count)
        grade, color, desc = self.get_privacy_grade()
        self.privacy_grade_changed.emit(grade, color, desc)

    def _on_load_finished(self, success: bool):
        if success and not self.is_internal_page:
            url_str = self.url().toString()
            title = self.title() or url_str
            self.storage.add_history(title, url_str)

        count = self.interceptor.get_blocked_count(self.current_domain)
        self.blocked_count_changed.emit(count)
        grade, color, desc = self.get_privacy_grade()
        self.privacy_grade_changed.emit(grade, color, desc)

    def zoom_in(self):
        self.setZoomFactor(min(self.zoomFactor() + 0.1, 3.0))

    def zoom_out(self):
        self.setZoomFactor(max(self.zoomFactor() - 0.1, 0.3))

    def zoom_reset(self):
        self.setZoomFactor(1.0)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        
        # Navigation
        back_act = menu.addAction("← Назад")
        back_act.setEnabled(self.history().canGoBack())
        back_act.triggered.connect(self.back)

        fwd_act = menu.addAction("→ Вперед")
        fwd_act.setEnabled(self.history().canGoForward())
        fwd_act.triggered.connect(self.forward)

        reload_act = menu.addAction("↻ Обновить")
        reload_act.triggered.connect(self.reload)

        menu.addSeparator()

        copy_act = menu.addAction("📋 Копировать адрес страницы")
        copy_act.triggered.connect(lambda: self.parent().copy_url(self.url().toString()) if hasattr(self.parent(), "copy_url") else None)

        bm_act = menu.addAction("⭐ Добавить в закладки")
        bm_act.triggered.connect(lambda: self.storage.add_bookmark(self.title(), self.url().toString()))

        menu.addSeparator()

        # DevTools / Inspect
        src_act = menu.addAction("📄 Исходный код страницы")
        src_act.triggered.connect(lambda: self.page().toHtml(lambda html: print("[Page Source]", html[:200])))

        menu.exec(event.globalPos())
