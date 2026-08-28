"""
TuxBrowser - Main Window
Provides the full browser UI: tabs, omnibox, security badges, bookmark bar, find bar, shield popover, and shortcuts.
"""

import os
import sys
from urllib.parse import urlparse
from typing import List, Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabBar, QStackedWidget, QTabWidget, QLineEdit, QToolButton, QToolBar,
    QPushButton, QLabel, QMenu, QDialog, QStatusBar,
    QMessageBox, QApplication
)
from PySide6.QtCore import Qt, QUrl, QSize, QPoint, QTimer
from PySide6.QtGui import QIcon, QKeySequence, QShortcut, QAction, QColor, QFont
from PySide6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEngineSettings,
    QWebEnginePage
)

from browser.src.tab_view import TuxTabView
from browser.src.theme import (
    TUX_STYLESHEET, get_icon_path, load_colored_icon,
    COLOR_TUX_GOLD, COLOR_GREEN, COLOR_RED, COLOR_ICE_CYAN
)
from browser.src.downloads import TuxDownloadManager
from browser.src.interceptor import strip_tracking_parameters
from browser.src.privacy_scripts import install_privacy_scripts


class TuxShieldPopover(QDialog):
    """Interactive popover showing security & tracker statistics for current website."""

    def __init__(self, domain: str, security_status: str, blocked_count: int, storage, interceptor, parent=None):
        super().__init__(parent, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self.domain = domain
        self.security_status = security_status
        self.storage = storage
        self.interceptor = interceptor
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #161b22;
                border: 1.5px solid #30363d;
                border-radius: 12px;
                padding: 16px;
                color: #f0f6fc;
            }
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                padding: 6px 12px;
                font-weight: 500;
            }
            QPushButton:hover {
                border-color: #f59e0b;
                background-color: #30363d;
            }
            QPushButton#toggleBtn {
                background-color: #f59e0b;
                color: #0b0f19;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        title_lbl = QLabel(f"🛡️ <b>Tux Shield & Приватность</b> — {domain or 'Внутренняя страница'}")
        title_lbl.setStyleSheet("font-size: 14px; color: #f59e0b;")
        header.addWidget(title_lbl)
        layout.addLayout(header)

        # Privacy Grade Card
        cur_tab = parent.current_tab() if parent and hasattr(parent, "current_tab") else None
        if cur_tab:
            grade, g_color, g_desc = cur_tab.get_privacy_grade()
        else:
            grade, g_color, g_desc = ("A+", "#10b981", "Внутренняя защита Tux")

        grade_card = QFrame(self)
        grade_card.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1117;
                border: 1.5px solid {g_color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        g_layout = QVBoxLayout(grade_card)
        g_layout.setSpacing(4)
        
        g_row = QHBoxLayout()
        g_badge_lbl = QLabel(f"<b style='font-size: 22px; color: {g_color};'>{grade}</b>")
        g_title_lbl = QLabel(f"<b>Рейтинг приватности (DuckDuckGo Grade)</b>")
        g_title_lbl.setStyleSheet("color: #f0f6fc; font-size: 13px;")
        g_row.addWidget(g_badge_lbl)
        g_row.addWidget(g_title_lbl)
        g_row.addStretch()
        g_layout.addLayout(g_row)

        g_desc_lbl = QLabel(g_desc)
        g_desc_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        g_desc_lbl.setWordWrap(True)
        g_layout.addWidget(g_desc_lbl)
        layout.addWidget(grade_card)

        # SSL Status
        ssl_box = QHBoxLayout()
        if security_status == "secure":
            ssl_lbl = QLabel("🔒 <b>Соединение защищено</b> (HTTPS 256-bit TLS)")
            ssl_lbl.setStyleSheet("color: #10b981; font-size: 12px;")
        elif security_status == "insecure":
            ssl_lbl = QLabel("⚠️ <b>Незащищенное соединение</b> (HTTP без шифрования)")
            ssl_lbl.setStyleSheet("color: #ef4444; font-size: 12px;")
        else:
            ssl_lbl = QLabel("🐧 <b>Системная страница Tux</b> (Внутренняя песочница)")
            ssl_lbl.setStyleSheet("color: #38bdf8; font-size: 12px;")
        ssl_box.addWidget(ssl_lbl)
        layout.addLayout(ssl_box)

        # Blocked count
        trackers_box = QHBoxLayout()
        t_lbl = QLabel(f"🚫 Заблокировано трекеров и рекламы: <b>{blocked_count}</b>")
        t_lbl.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        trackers_box.addWidget(t_lbl)
        layout.addLayout(trackers_box)

        # Whitelist toggle
        if domain:
            is_whitelisted = storage.is_domain_whitelisted(domain)
            self.toggle_btn = QPushButton("Разблокировать трекеры для этого сайта" if not is_whitelisted else "Включить защиту Tux Shield")
            self.toggle_btn.clicked.connect(self._toggle_whitelist)
            layout.addWidget(self.toggle_btn)

        # Full stats link
        stats_btn = QPushButton("📊 Открыть центр безопасности (tux://shield)")
        stats_btn.clicked.connect(self._open_stats)
        layout.addWidget(stats_btn)

    def _toggle_whitelist(self):
        self.storage.toggle_domain_whitelist(self.domain)
        self.close()
        if self.parent():
            self.parent().reload_current_tab()

    def _open_stats(self):
        self.close()
        if self.parent():
            self.parent().open_url("tux://shield")


class TuxBrowserWindow(QMainWindow):
    """Main TuxBrowser Window."""

    def __init__(self, profile: QWebEngineProfile, storage, interceptor, ghost_manager, assets_dir: str, is_incognito: bool = False):
        super().__init__()
        self.profile = profile
        self.storage = storage
        self.interceptor = interceptor
        self.ghost_manager = ghost_manager
        self.assets_dir = assets_dir
        self.is_incognito = is_incognito
        self.download_manager = TuxDownloadManager(self)
        self.closed_tab_history: List[str] = []
        self.last_privacy_alert_sound_time = 0.0
        self.alert_sound = None

        # Connect download handling
        self.profile.downloadRequested.connect(self.download_manager.handle_download)

        # Window Appearance
        self.setWindowTitle("TuxBrowser 🐧 (Linux Security Edition)" if not is_incognito else "TuxBrowser [GHOST MODE 👻]")
        self.resize(1180, 780)
        self.setMinimumSize(800, 500)
        self.setStyleSheet(TUX_STYLESHEET)

        # Install Anti-Fingerprint & GPC user scripts
        install_privacy_scripts(self.profile)

        # Set App Icon
        icon_path = get_icon_path(assets_dir, "tux.svg")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Main Layout
        self._init_ui()
        self._init_shortcuts()

        # Connect interceptor alert callback
        self.interceptor.on_privacy_alert_callback = self._on_privacy_alert

        # Connect Ghost Manager events
        if self.ghost_manager:
            self.ghost_manager.status_changed.connect(self._update_ghost_ui)
            self.ghost_manager.ip_updated.connect(self._on_ip_updated)
            self.ghost_manager.tz_updated.connect(self._on_tz_updated)
            self.ghost_manager.lang_updated.connect(self._on_lang_updated)
            self.ghost_manager.tor_error.connect(self._on_tor_error)
            self._update_ghost_ui(self.ghost_manager.get_status())

        # Open initial tab
        initial_url = "tux://home"
        self.add_new_tab(initial_url, "🐧 Tux Startpage")

    def _init_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout(central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 1. Firefox Proton Top Tab Strip (Tabs on Top!)
        self.tab_strip = QWidget(self)
        self.tab_strip.setObjectName("tabStrip")
        tab_layout = QHBoxLayout(self.tab_strip)
        tab_layout.setContentsMargins(4, 2, 4, 0)
        tab_layout.setSpacing(4)

        self.tab_bar = QTabBar(self)
        self.tab_bar.setTabsClosable(True)
        self.tab_bar.setMovable(True)
        self.tab_bar.setDrawBase(False)
        self.tab_bar.setElideMode(Qt.TextElideMode.ElideRight)
        self.tab_bar.currentChanged.connect(self._on_tab_switched)
        self.tab_bar.tabCloseRequested.connect(self.close_tab)
        tab_layout.addWidget(self.tab_bar)

        self.new_tab_btn = QToolButton(self)
        self.new_tab_btn.setObjectName("newTabBtn")
        self.new_tab_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "plus.svg")))
        self.new_tab_btn.setToolTip("Новая вкладка (Ctrl+T)")
        self.new_tab_btn.clicked.connect(lambda: self.add_new_tab())
        tab_layout.addWidget(self.new_tab_btn)
        tab_layout.addStretch()

        self.main_layout.addWidget(self.tab_strip)

        # 2. Firefox Navigation Toolbar (Below Tabs)
        self.toolbar = QToolBar("Navigation", self)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(18, 18))
        self.main_layout.addWidget(self.toolbar)
        self._build_toolbar()

        # 3. Firefox Bookmarks Bar (Below Toolbar)
        self.bookmarks_bar = QToolBar("Bookmarks", self)
        self.bookmarks_bar.setObjectName("bookmarksBar")
        self.bookmarks_bar.setMovable(False)
        self.bookmarks_bar.setIconSize(QSize(14, 14))
        self.main_layout.addWidget(self.bookmarks_bar)
        self._build_bookmarks_bar()

        # 4. Web View Container (Stacked Widget)
        self.stack = QStackedWidget(self)
        self.main_layout.addWidget(self.stack)

        # 5. Find in Page Bar (Collapsible)
        self._build_find_bar()

        # 6. Status Bar
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("🦊 FishTux готов к защищенной работе", 4000)

        self.zoom_lbl = QLabel("100%", self)
        self.zoom_lbl.setStyleSheet("color: #bfbfc9; font-size: 11px; margin-right: 8px;")
        self.status_bar.addPermanentWidget(self.zoom_lbl)

    def _build_toolbar(self):
        # Back
        self.back_btn = QToolButton(self)
        self.back_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "arrow-left.svg")))
        self.back_btn.setToolTip("Назад (Alt+Left)")
        self.back_btn.clicked.connect(self._go_back)
        self.toolbar.addWidget(self.back_btn)

        # Forward
        self.fwd_btn = QToolButton(self)
        self.fwd_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "arrow-right.svg")))
        self.fwd_btn.setToolTip("Вперед (Alt+Right)")
        self.fwd_btn.clicked.connect(self._go_forward)
        self.toolbar.addWidget(self.fwd_btn)

        # Reload / Stop
        self.reload_btn = QToolButton(self)
        self.reload_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "rotate-cw.svg")))
        self.reload_btn.setToolTip("Обновить (Ctrl+R / F5)")
        self.reload_btn.clicked.connect(self._reload_or_stop)
        self.toolbar.addWidget(self.reload_btn)

        # Home
        self.home_btn = QToolButton(self)
        self.home_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "home.svg")))
        self.home_btn.setToolTip("Главная страница (Alt+Home)")
        self.home_btn.clicked.connect(lambda: self.open_url(self.storage.get_setting("home_page", "tux://home")))
        self.toolbar.addWidget(self.home_btn)

        # Omnibox Address Container (Firefox AwesomeBar)
        self.omnibox_container = QWidget(self)
        omni_layout = QHBoxLayout(self.omnibox_container)
        omni_layout.setContentsMargins(0, 0, 0, 0)
        omni_layout.setSpacing(0)

        # Omnibox Input
        self.omnibox = QLineEdit(self)
        self.omnibox.setObjectName("omnibox")
        self.omnibox.setPlaceholderText("Поиск в TuxFind или введите адрес...")
        self.omnibox.returnPressed.connect(self._navigate_from_omnibox)
        omni_layout.addWidget(self.omnibox)

        # Overlay Security Badge Button (inside omnibox left)
        self.sec_badge_btn = QPushButton(self.omnibox)
        self.sec_badge_btn.setObjectName("securityBadge")
        self.sec_badge_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "lock.svg")))
        self.sec_badge_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sec_badge_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.sec_badge_btn.clicked.connect(self._show_shield_popover)
        self.sec_badge_btn.resize(24, 24)

        # Overlay DuckDuckGo / Privacy Grade Badge (inside omnibox left next to lock)
        self.grade_badge_btn = QPushButton("A+", self.omnibox)
        self.grade_badge_btn.setObjectName("gradeBadge")
        self.grade_badge_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.grade_badge_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.grade_badge_btn.setToolTip("DuckDuckGo Privacy Grade: A+ (Максимальная приватность)")
        self.grade_badge_btn.clicked.connect(self._show_shield_popover)
        self.grade_badge_btn.resize(32, 22)

        # Overlay Star (Bookmark) Button (inside omnibox right)
        self.star_btn = QPushButton(self.omnibox)
        self.star_btn.setObjectName("securityBadge")
        self.star_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "star.svg")))
        self.star_btn.setToolTip("Добавить в закладки (Ctrl+D)")
        self.star_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.star_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.star_btn.clicked.connect(self._toggle_current_bookmark)
        self.star_btn.resize(26, 24)

        # Overlay Shield Counter Badge (inside omnibox right)
        self.shield_badge_btn = QPushButton("🛡️ 0", self.omnibox)
        self.shield_badge_btn.setObjectName("shieldBadge")
        self.shield_badge_btn.setToolTip("FishTux Shield: Блокировщик трекеров")
        self.shield_badge_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.shield_badge_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.shield_badge_btn.clicked.connect(self._show_shield_popover)
        self.shield_badge_btn.resize(50, 22)

        self.toolbar.addWidget(self.omnibox_container)

        # Fire Button (Tux Burner 🔥 - DuckDuckGo Flame Wipe)
        self.fire_btn = QToolButton(self)
        self.fire_btn.setObjectName("fireBtn")
        self.fire_btn.setText("🔥")
        self.fire_btn.setToolTip("Tux Burner: Очистить все вкладки, куки и кэш 🔥 (Ctrl+Shift+Del)")
        self.fire_btn.clicked.connect(self._burn_session)
        self.toolbar.addWidget(self.fire_btn)

        # Downloads Button
        self.downloads_btn = QToolButton(self)
        self.downloads_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "download.svg")))
        self.downloads_btn.setToolTip("Загрузки (Ctrl+J)")
        self.downloads_btn.clicked.connect(self._show_downloads_info)
        self.toolbar.addWidget(self.downloads_btn)

        # History Button
        self.history_btn = QToolButton(self)
        self.history_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "history.svg")))
        self.history_btn.setToolTip("История (Ctrl+H)")
        self.history_btn.clicked.connect(lambda: self.open_url("tux://history"))
        self.toolbar.addWidget(self.history_btn)

        # Ghost / Tor Mode Button
        self.ghost_btn = QToolButton(self)
        self.ghost_btn.setObjectName("ghostBtn")
        self.ghost_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "ghost.svg")))
        self.ghost_btn.setText(" 👻 Ghost: ВЫКЛ")
        self.ghost_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.ghost_btn.setToolTip("Tux Ghost: Включить анонимный Tor-маршрут (Скрыть IP)")
        self.ghost_btn.clicked.connect(self._toggle_ghost_mode)
        self.toolbar.addWidget(self.ghost_btn)

        # Rotate IP Button (New Identity)
        self.rotate_ip_btn = QToolButton(self)
        self.rotate_ip_btn.setObjectName("rotateIpBtn")
        self.rotate_ip_btn.setText("🔄 Сменить IP")
        self.rotate_ip_btn.setToolTip("Tux Ghost: Получить новый IP-адрес (Tor New Identity) [Ctrl+Alt+R]")
        self.rotate_ip_btn.clicked.connect(self._rotate_ghost_ip)
        self.rotate_ip_btn.setVisible(True)
        self.toolbar.addWidget(self.rotate_ip_btn)

        # Settings / Menu
        self.menu_btn = QToolButton(self)
        self.menu_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "menu.svg")))
        self.menu_btn.setToolTip("Меню TuxBrowser")
        self.menu_btn.clicked.connect(self._show_main_menu)
        self.toolbar.addWidget(self.menu_btn)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Position internal buttons in omnibox & bring to front
        w = self.omnibox.width()
        h = self.omnibox.height()
        self.sec_badge_btn.move(6, (h - 24) // 2)
        self.grade_badge_btn.move(34, (h - 22) // 2)
        self.shield_badge_btn.move(w - 88, (h - 22) // 2)
        self.star_btn.move(w - 32, (h - 24) // 2)
        self.sec_badge_btn.raise_()
        self.grade_badge_btn.raise_()
        self.shield_badge_btn.raise_()
        self.star_btn.raise_()

    def _build_bookmarks_bar(self):
        self.bookmarks_bar.clear()
        bookmarks = self.storage.get_bookmarks()
        for b in bookmarks[:8]:
            btn = QToolButton(self)
            btn.setText(b.get("title", ""))
            btn.setToolTip(b.get("url", ""))
            btn.clicked.connect(lambda checked, url=b.get("url"): self.open_url(url))
            self.bookmarks_bar.addWidget(btn)

    def _build_find_bar(self):
        self.find_bar = QWidget(self)
        self.find_bar.setObjectName("findBar")
        self.find_bar.setVisible(False)
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(12, 4, 12, 4)
        find_layout.setSpacing(8)

        find_lbl = QLabel("🔍 Найти:", self)
        find_layout.addWidget(find_lbl)

        self.find_input = QLineEdit(self)
        self.find_input.setPlaceholderText("Поиск на странице...")
        self.find_input.textChanged.connect(self._on_find_text)
        self.find_input.returnPressed.connect(self._find_next)
        find_layout.addWidget(self.find_input)

        prev_btn = QToolButton(self)
        prev_btn.setText("▲")
        prev_btn.setToolTip("Предыдущее совпадение")
        prev_btn.clicked.connect(self._find_prev)
        find_layout.addWidget(prev_btn)

        next_btn = QToolButton(self)
        next_btn.setText("▼")
        next_btn.setToolTip("Следующее совпадение")
        next_btn.clicked.connect(self._find_next)
        find_layout.addWidget(next_btn)

        close_find_btn = QToolButton(self)
        close_find_btn.setText("✕")
        close_find_btn.clicked.connect(lambda: self.find_bar.setVisible(False))
        find_layout.addWidget(close_find_btn)

        self.main_layout.addWidget(self.find_bar)

    def _init_shortcuts(self):
        # Ctrl+T: New Tab
        QShortcut(QKeySequence("Ctrl+T"), self, lambda: self.add_new_tab())
        # Ctrl+W: Close Tab
        QShortcut(QKeySequence("Ctrl+W"), self, self._close_current_tab)
        # Ctrl+Shift+T: Reopen Tab
        QShortcut(QKeySequence("Ctrl+Shift+T"), self, self._reopen_closed_tab)
        # Ctrl+L / Alt+D: Focus Omnibox
        QShortcut(QKeySequence("Ctrl+L"), self, self.omnibox.selectAll)
        QShortcut(QKeySequence("Alt+D"), self, self.omnibox.selectAll)
        # Ctrl+R / F5: Reload
        QShortcut(QKeySequence("Ctrl+R"), self, self.reload_current_tab)
        QShortcut(QKeySequence("F5"), self, self.reload_current_tab)
        # Ctrl+H: History
        QShortcut(QKeySequence("Ctrl+H"), self, lambda: self.open_url("tux://history"))
        # Ctrl+B: Bookmarks Bar Toggle
        QShortcut(QKeySequence("Ctrl+B"), self, self._toggle_bookmarks_bar)
        # Ctrl+F: Find
        QShortcut(QKeySequence("Ctrl+F"), self, self._open_find_bar)
        # Zoom shortcuts
        QShortcut(QKeySequence("Ctrl+="), self, self._zoom_in)
        QShortcut(QKeySequence("Ctrl+-"), self, self._zoom_out)
        QShortcut(QKeySequence("Ctrl+0"), self, self._zoom_reset)
        # F11: Fullscreen
        QShortcut(QKeySequence("F11"), self, self._toggle_fullscreen)
        # Ctrl+Shift+Del: Tux Burner (Fire Wipe)
        QShortcut(QKeySequence("Ctrl+Shift+Del"), self, self._burn_session)
        QShortcut(QKeySequence("Ctrl+Shift+Delete"), self, self._burn_session)
        QShortcut(QKeySequence("Ctrl+Shift+X"), self, self._burn_session)
        # Ctrl+Alt+R / Ctrl+Shift+U: Rotate IP (New Identity)
        QShortcut(QKeySequence("Ctrl+Alt+R"), self, self._rotate_ghost_ip)
        QShortcut(QKeySequence("Ctrl+Shift+U"), self, self._rotate_ghost_ip)

    # ----------------- Tab Management -----------------
    def current_tab(self) -> Optional[TuxTabView]:
        return self.stack.currentWidget()

    def add_new_tab(self, url: Optional[str] = None, title: str = "Новая вкладка 🐧") -> TuxTabView:
        if url is None:
            url = self.storage.get_setting("home_page", "tux://home")
        tab = TuxTabView(self.profile, self.interceptor, self.storage, self)
        
        # Connect tab signals
        tab.title_changed.connect(lambda t: self._update_tab_title(tab, t))
        tab.icon_changed.connect(lambda ico: self._update_tab_icon(tab, ico))
        tab.url_changed.connect(lambda u: self._on_tab_url_changed(tab, u))
        tab.security_changed.connect(self._on_security_changed)
        tab.load_progress.connect(self._on_load_progress)
        tab.blocked_count_changed.connect(self._on_blocked_count_changed)
        tab.privacy_grade_changed.connect(self._on_privacy_grade_changed)
        tab.privacy_alert.connect(self._on_privacy_alert)

        idx = self.tab_bar.addTab(title)
        self.stack.addWidget(tab)
        self.tab_bar.setCurrentIndex(idx)
        self.stack.setCurrentIndex(idx)
        clean_url = strip_tracking_parameters(url)
        tab.load(QUrl(clean_url))
        return tab

    def close_tab(self, index: int):
        if self.tab_bar.count() <= 1:
            # Keep at least 1 tab, navigate to home
            tab = self.stack.widget(0)
            if tab:
                home_url = self.storage.get_setting("home_page", "tux://home")
                tab.load(QUrl(home_url))
            return

        tab = self.stack.widget(index)
        if tab:
            self.closed_tab_history.append(tab.url().toString())
            self.tab_bar.removeTab(index)
            self.stack.removeWidget(tab)
            tab.deleteLater()
            self._on_tab_switched(self.tab_bar.currentIndex())

    def _close_current_tab(self):
        self.close_tab(self.tab_bar.currentIndex())

    def _reopen_closed_tab(self):
        if self.closed_tab_history:
            last_url = self.closed_tab_history.pop()
            self.add_new_tab(last_url)

    def _on_tab_switched(self, index: int):
        self.stack.setCurrentIndex(index)
        tab = self.current_tab()
        if tab:
            self.omnibox.setText(tab.url().toString())
            self._update_star_state(tab.url().toString())
            self._update_security_badge(tab.security_status)
            count = self.interceptor.get_blocked_count(tab.current_domain)
            self.shield_badge_btn.setText(f"🛡️ {count}")
            self.zoom_lbl.setText(f"{int(tab.zoomFactor() * 100)}%")
            grade, color, desc = tab.get_privacy_grade()
            self._on_privacy_grade_changed(grade, color, desc)

    def _on_privacy_grade_changed(self, grade: str, color: str, desc: str):
        self.grade_badge_btn.setText(grade)
        self.grade_badge_btn.setStyleSheet(
            f"background-color: {color}22; border: 1px solid {color}88; color: {color}; border-radius: 6px; font-weight: 800; font-size: 11px; padding: 1px 5px;"
        )
        self.grade_badge_btn.setToolTip(f"Рейтинг приватности DuckDuckGo: {grade}\n{desc}")

    def _burn_session(self):
        """Tux Burner / Panic Button: Nukes all open tabs, cookies, storage, cache, rotates Tor circuit and purges RAM."""
        import gc
        while self.tab_bar.count() > 1:
            tab = self.stack.widget(1)
            self.tab_bar.removeTab(1)
            self.stack.removeWidget(tab)
            tab.deleteLater()

        first_tab = self.stack.widget(0)
        if first_tab:
            first_tab.load(QUrl("tux://home"))

        self.profile.clearHttpCache()
        self.profile.cookieStore().deleteAllCookies()
        self.closed_tab_history.clear()
        self.interceptor.page_blocked_counts.clear()

        # Rotate Tor identity if active
        if self.ghost_manager and self.ghost_manager.is_ghost_active:
            self.ghost_manager.rotate_identity()

        # Force RAM garbage collection
        gc.collect()

        self.status_bar.showMessage("🚨 Экстренная очистка выполнена: Вкладки закрыты, куки стерты, Tor-цепочка обновлена!", 6000)

    def _update_tab_title(self, tab: TuxTabView, title: str):
        idx = self.stack.indexOf(tab)
        if idx >= 0:
            short_title = (title[:18] + "...") if len(title) > 20 else title
            self.tab_bar.setTabText(idx, short_title)
            self.tab_bar.setTabToolTip(idx, title)

    def _update_tab_icon(self, tab: TuxTabView, icon: QIcon):
        idx = self.stack.indexOf(tab)
        if idx >= 0 and not icon.isNull():
            self.tab_bar.setTabIcon(idx, icon)

    def _on_tab_url_changed(self, tab: TuxTabView, qurl: QUrl):
        if tab == self.current_tab():
            url_str = qurl.toString()
            self.omnibox.setText(url_str)
            self._update_star_state(url_str)

    def _on_security_changed(self, status: str, details: str):
        self._update_security_badge(status)
        self.status_bar.showMessage(details, 3000)

    def _update_security_badge(self, status: str):
        if status == "secure":
            self.sec_badge_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "lock.svg")))
            self.sec_badge_btn.setToolTip("Соединение HTTPS защищено шифрованием")
        elif status == "insecure":
            self.sec_badge_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "lock-unsecure.svg")))
            self.sec_badge_btn.setToolTip("Внимание: HTTP соединение не зашифровано")
        else:
            self.sec_badge_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "tux.svg")))
            self.sec_badge_btn.setToolTip("Внутренняя изолированная страница Tux")

    def _on_load_progress(self, progress: int):
        if progress < 100:
            self.reload_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "x.svg")))
            self.reload_btn.setToolTip("Остановить загрузку (Esc)")
        else:
            self.reload_btn.setIcon(QIcon(get_icon_path(self.assets_dir, "rotate-cw.svg")))
            self.reload_btn.setToolTip("Обновить (Ctrl+R / F5)")

    def _on_blocked_count_changed(self, count: int):
        self.shield_badge_btn.setText(f"🛡️ {count}")

    # ----------------- Navigation -----------------
    def open_url(self, url_str: str):
        tab = self.current_tab()
        if tab:
            clean_url = strip_tracking_parameters(url_str)
            tab.load(QUrl(clean_url))

    def _navigate_from_omnibox(self):
        text = self.omnibox.text().strip()
        if not text:
            return

        from browser.src.interceptor import resolve_input_to_url
        engine = self.storage.get_setting("search_engine", "TuxFind")
        engines_map = self.storage.get_setting("search_engines", {})
        template = engines_map.get(engine, "tux://search?q={query}")
        target_url = resolve_input_to_url(text, template)

        clean_target = strip_tracking_parameters(target_url)
        self.open_url(clean_target)

    def _go_back(self):
        tab = self.current_tab()
        if tab:
            tab.back()

    def _go_forward(self):
        tab = self.current_tab()
        if tab:
            tab.forward()

    def _reload_or_stop(self):
        tab = self.current_tab()
        if tab:
            tab.reload()

    def reload_current_tab(self):
        tab = self.current_tab()
        if tab:
            tab.reload()

    # ----------------- Bookmarks -----------------
    def _update_star_state(self, url: str):
        is_bm = self.storage.is_bookmarked(url)
        star_icon = "star-filled.svg" if is_bm else "star.svg"
        self.star_btn.setIcon(QIcon(get_icon_path(self.assets_dir, star_icon)))

    def _toggle_current_bookmark(self):
        tab = self.current_tab()
        if not tab:
            return
        url = tab.url().toString()
        title = tab.title() or url
        if self.storage.is_bookmarked(url):
            self.storage.remove_bookmark(url)
            self.status_bar.showMessage("Закладка удалена", 2000)
        else:
            self.storage.add_bookmark(title, url)
            self.status_bar.showMessage("⭐ Закладка сохранена!", 2000)
        self._update_star_state(url)
        self._build_bookmarks_bar()

    def _toggle_bookmarks_bar(self):
        self.bookmarks_bar.setVisible(not self.bookmarks_bar.isVisible())

    # ----------------- Find in Page -----------------
    def _open_find_bar(self):
        self.find_bar.setVisible(True)
        self.find_input.setFocus()
        self.find_input.selectAll()

    def _on_find_text(self, text: str):
        tab = self.current_tab()
        if tab:
            tab.findText(text)

    def _find_next(self):
        tab = self.current_tab()
        if tab:
            tab.findText(self.find_input.text())

    def _find_prev(self):
        tab = self.current_tab()
        if tab:
            tab.findText(self.find_input.text(), QWebEnginePage.FindFlag.FindBackward)

    # ----------------- Zoom -----------------
    def _zoom_in(self):
        tab = self.current_tab()
        if tab:
            tab.zoom_in()
            self.zoom_lbl.setText(f"{int(tab.zoomFactor() * 100)}%")

    def _zoom_out(self):
        tab = self.current_tab()
        if tab:
            tab.zoom_out()
            self.zoom_lbl.setText(f"{int(tab.zoomFactor() * 100)}%")

    def _zoom_reset(self):
        tab = self.current_tab()
        if tab:
            tab.zoom_reset()
            self.zoom_lbl.setText("100%")

    def _toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    # ----------------- Shield & Popovers -----------------
    def _show_shield_popover(self):
        tab = self.current_tab()
        if not tab:
            return
        domain = tab.current_domain
        count = self.interceptor.get_blocked_count(domain)
        popover = TuxShieldPopover(domain, tab.security_status, count, self.storage, self.interceptor, self)
        pos = self.omnibox.mapToGlobal(QPoint(0, self.omnibox.height() + 4))
        popover.move(pos)
        popover.exec()

    def _show_downloads_info(self):
        downloads = self.download_manager.active_downloads
        msg = f"Активных загрузок: {len(downloads)}\nПапка: {self.download_manager.default_dir}"
        QMessageBox.information(self, "📥 Загрузки TuxBrowser", msg)

    def _open_ghost_window(self):
        from browser.src.privacy_scripts import install_privacy_scripts
        ghost_profile = QWebEngineProfile(self)  # off-the-record / in-memory profile
        install_privacy_scripts(ghost_profile)
        ghost_profile.settings().setAttribute(QWebEngineSettings.WebAttribute.DnsPrefetchEnabled, False)
        ghost_profile.settings().setAttribute(QWebEngineSettings.WebAttribute.HyperlinkAuditingEnabled, False)
        ghost_profile.settings().setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, True)
        ghost_win = TuxBrowserWindow(ghost_profile, self.storage, self.interceptor, self.ghost_manager, self.assets_dir, is_incognito=True)
        ghost_win.show()

    def _show_main_menu(self):
        menu = QMenu(self)
        menu.addAction("⭐ Закладки (Ctrl+B)").triggered.connect(lambda: self.open_url("tux://bookmarks"))
        menu.addAction("📜 История (Ctrl+H)").triggered.connect(lambda: self.open_url("tux://history"))
        menu.addAction("🛡️ Tux Shield — Статистика").triggered.connect(lambda: self.open_url("tux://shield"))
        menu.addAction("⚙️ Настройки безопасности").triggered.connect(lambda: self.open_url("tux://settings"))
        menu.addSeparator()
        menu.addAction("🔄 Сменить IP / Tor-маршрут (Ctrl+Alt+R)").triggered.connect(self._rotate_ghost_ip)
        menu.addAction("👻 Новое приватное окно (Ghost Mode)").triggered.connect(self._open_ghost_window)
        menu.addSeparator()
        menu.addAction("ℹ️ О TuxBrowser").triggered.connect(lambda: self.open_url("tux://about"))
        menu.addAction("🚪 Выход").triggered.connect(self.close)

        pos = self.menu_btn.mapToGlobal(QPoint(0, self.menu_btn.height()))
        menu.exec(pos)

    # ----------------- Tux Ghost Actions -----------------
    def _toggle_ghost_mode(self):
        if not self.ghost_manager:
            return
        if self.ghost_manager.is_ghost_active:
            self.ghost_manager.disable_ghost_mode()
            self._update_ghost_ui(self.ghost_manager.get_status())
            self.statusBar().showMessage("🟢 Режим Tux Ghost ВЫКЛЮЧЕН. Прямое стабильное соединение.", 4000)
        else:
            self.ghost_btn.setText(" ⏳ Ghost...")
            self.statusBar().showMessage("👻 Запуск и проверка подключения к Tor...", 4000)
            self.ghost_manager.toggle_ghost_mode()

    def _on_tor_error(self, err_msg: str):
        self.statusBar().showMessage(f"⚠️ {err_msg}", 8000)
        if hasattr(self, "ghost_btn"):
            self.ghost_btn.setText(" 👻 Ghost: ВЫКЛ")
            self.ghost_btn.setToolTip(f"⚠️ {err_msg}")
            self.ghost_btn.setProperty("ghostActive", "false")
            self.ghost_btn.style().unpolish(self.ghost_btn)
            self.ghost_btn.style().polish(self.ghost_btn)

    def _rotate_ghost_ip(self):
        if not self.ghost_manager:
            return
        if not self.ghost_manager.is_ghost_active:
            self.statusBar().showMessage("👻 Включение режима Tux Ghost для ротации IP...", 3500)
            self._toggle_ghost_mode()
            return
        self.rotate_ip_btn.setText("⏳ Ротация...")
        success, msg = self.ghost_manager.rotate_identity()
        self.statusBar().showMessage(f"🔄 {msg}", 4000)
        QTimer.singleShot(1200, lambda: self.rotate_ip_btn.setText("🔄 Сменить IP"))
        
        tab = self.current_tab()
        if tab:
            QTimer.singleShot(1000, lambda: tab.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache))

    def _update_ghost_ui(self, status: dict):
        if not hasattr(self, "ghost_btn") or not hasattr(self, "rotate_ip_btn"):
            return
        active = status.get("is_active", False)
        mode = status.get("mode", "direct")
        ip = status.get("ip", "...")
        country = status.get("country", "...")
        bs_status = status.get("bootstrap_status", "")

        self.ghost_btn.setProperty("ghostActive", "true" if active else "false")
        self.ghost_btn.style().unpolish(self.ghost_btn)
        self.ghost_btn.style().polish(self.ghost_btn)

        if active:
            self.ghost_btn.setText(" 👻 Ghost: ВКЛ")
            self.ghost_btn.setToolTip(f"👻 Tux Ghost: АКТИВЕН ({mode.upper()})\nIP: {ip} ({country})\nНажмите для выключения")
            self.statusBar().showMessage(f"🟢 Tux Ghost активен. IP: {ip} ({country})", 5000)
        elif self.ghost_manager and self.ghost_manager.is_tor_running and not self.ghost_manager.is_bootstrapped:
            # Still connecting / bootstrapping
            display_text = bs_status if len(bs_status) <= 24 else bs_status[:22] + "..."
            self.ghost_btn.setText(f" ⏳ {display_text}")
            self.ghost_btn.setToolTip(f"Подключение к защищенной сети: {bs_status}")
            self.statusBar().showMessage(f"👻 {bs_status}", 4000)
        else:
            self.ghost_btn.setText(" 👻 Ghost: ВЫКЛ")
            self.ghost_btn.setToolTip("👻 Tux Ghost: ВЫКЛ (Прямое соединение)\nНажмите для включения защиты IP")

        self.rotate_ip_btn.setVisible(True)

    def _on_ip_updated(self, ip: str, country: str):
        if self.ghost_manager:
            self._update_ghost_ui(self.ghost_manager.get_status())

    def _on_tz_updated(self, tz: str):
        if tz:
            active_lang = self.storage.get_setting("active_language", "en-US")
            active_langs = self.storage.get_setting("active_languages", ["en-US", "en"])
            install_privacy_scripts(self.profile, tz, active_lang, active_langs)
            print(f"[TuxGhost] Precision Timezone Aligned to IP GeoIP -> {tz}")
            try:
                from browser.src.privacy_scripts import get_anti_fingerprint_js
                js_code = get_anti_fingerprint_js(tz, active_lang, active_langs)
                for i in range(self.tab_widget.count()):
                    tab = self.tab_widget.widget(i)
                    if tab and hasattr(tab, "page") and tab.page():
                        tab.page().runJavaScript(js_code)
            except Exception:
                pass

    def _on_lang_updated(self, primary_lang: str, languages: list):
        if primary_lang:
            active_tz = self.storage.get_setting("active_timezone", "Europe/Amsterdam")
            install_privacy_scripts(self.profile, active_tz, primary_lang, languages)
            print(f"[TuxGhost] Precision Language Aligned to IP GeoIP -> {primary_lang}")
            try:
                from browser.src.privacy_scripts import get_anti_fingerprint_js
                js_code = get_anti_fingerprint_js(active_tz, primary_lang, languages)
                for i in range(self.tab_widget.count()):
                    tab = self.tab_widget.widget(i)
                    if tab and hasattr(tab, "page") and tab.page():
                        tab.page().runJavaScript(js_code)
            except Exception:
                pass

    def _on_privacy_alert(self, reason: str, origin: str):
        """Triggered whenever a website attempts to access sensors, camera, mic, or harvest IP/fingerprints."""
        now = time.time()
        # Audio chime with throttling (at most 1 sound per 1.5 seconds)
        if self.storage.get_setting("privacy_sound_alerts", True) and (now - self.last_privacy_alert_sound_time > 1.5):
            self.last_privacy_alert_sound_time = now
            self._play_privacy_alert_sound()

        # Display warning on status bar
        origin_text = f"на {origin}" if origin else ""
        self.statusBar().showMessage(f"🛡️ [Tux Shield] Заблокировано считывание данных: {reason} {origin_text}", 6000)
        print(f"[TuxShield Alert] {reason} ({origin})")

    def _play_privacy_alert_sound(self):
        """Plays the futuristic privacy alert chime."""
        sound_path = os.path.join(self.assets_dir, "sounds", "privacy_alert.wav")
        played = False

        # 1. Native Linux sound system (paplay / pw-play / aplay / canberra-gtk-play)
        for player in ["paplay", "pw-play", "aplay", "canberra-gtk-play"]:
            if shutil.which(player):
                try:
                    if player == "canberra-gtk-play":
                        subprocess.Popen([player, "-f", sound_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        subprocess.Popen([player, sound_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    played = True
                    break
                except Exception:
                    pass

        # 2. QtMultimedia QSoundEffect fallback
        if not played:
            try:
                from PySide6.QtMultimedia import QSoundEffect
                if not self.alert_sound and os.path.exists(sound_path):
                    self.alert_sound = QSoundEffect(self)
                    self.alert_sound.setSource(QUrl.fromLocalFile(sound_path))
                    self.alert_sound.setVolume(0.8)
                if self.alert_sound:
                    self.alert_sound.play()
                    played = True
            except Exception:
                pass

        # 3. System bell fallback
        if not played:
            try:
                from PySide6.QtWidgets import QApplication
                QApplication.beep()
            except Exception:
                pass

    def closeEvent(self, event):
        if self.ghost_manager and not self.is_incognito:
            self.ghost_manager.shutdown()
        super().closeEvent(event)
