"""
TuxBrowser - Firefox Proton Dark Theme & Stylesheet (QSS)
Defines the visual design system, colors, icons, and Qt stylesheets matching Firefox Proton Dark.
"""

import os
from PySide6.QtGui import QIcon, QPixmap, QColor, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtCore import QSize, Qt


# Firefox Proton Brand Palette
COLOR_BG_DARK = "#1c1b22"           # Firefox root dark background
COLOR_SURFACE = "#2b2a33"           # Firefox toolbar & popups
COLOR_SURFACE_HOVER = "#42414d"     # Firefox tab active & hover
COLOR_BORDER = "#38383d"            # Subtle card border
COLOR_BORDER_FOCUS = "#00ddff"      # Firefox neon cyan focus
COLOR_FIREFOX_ORANGE = "#ff7139"    # Firefox flame orange
COLOR_FIREFOX_PURPLE = "#9059ff"    # Firefox purple
COLOR_FIREFOX_CYAN = "#00ddff"      # Firefox cyan
COLOR_TEXT_MAIN = "#fbfbfe"         # Firefox primary text
COLOR_TEXT_MUTED = "#bfbfc9"        # Firefox muted text
COLOR_GREEN = "#2ac3a2"             # Firefox shield green
COLOR_RED = "#ff3b30"               # Firefox danger red
COLOR_TUX_GOLD = "#ff7139"
COLOR_ICE_CYAN = "#00ddff"


def get_icon_path(assets_dir: str, name: str) -> str:
    return os.path.join(assets_dir, "icons", name)


def load_colored_icon(icon_path: str, size: int = 20, color: QColor = None) -> QIcon:
    """Loads an SVG icon and optionally recolors it."""
    if not os.path.exists(icon_path):
        return QIcon()

    renderer = QSvgRenderer(icon_path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)

    if color is not None:
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        painter.fillRect(pixmap.rect(), color)

    painter.end()
    return QIcon(pixmap)


TUX_STYLESHEET = """
/* Firefox Proton Global Application Style */
QMainWindow, QWidget {
    background-color: #1c1b22;
    color: #fbfbfe;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", "Ubuntu", sans-serif;
    font-size: 13px;
}

/* Firefox Proton Top Tab Strip */
QWidget#tabStrip {
    background-color: #1c1b22;
    padding: 3px 6px 0px 6px;
    border-bottom: none;
}

QTabBar {
    background-color: transparent;
    qproperty-drawBase: 0;
}

/* Firefox Floating Detached Tab Pills */
QTabBar::tab {
    background-color: transparent;
    color: #bfbfc9;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 7px 14px;
    margin: 3px 3px;
    min-width: 140px;
    max-width: 220px;
    font-size: 12px;
}

QTabBar::tab:hover:!selected {
    background-color: #2b2a33;
    color: #fbfbfe;
}

QTabBar::tab:selected {
    background-color: #42414d;
    color: #fbfbfe;
    border: 1.5px solid #00ddff;
    font-weight: 600;
}

QTabBar::close-button {
    image: none;
    subcontrol-position: right;
    margin-left: 6px;
    padding: 2px;
    border-radius: 4px;
}

QTabBar::close-button:hover {
    background-color: #52525e;
}

QToolButton#newTabBtn {
    background-color: transparent;
    border: none;
    border-radius: 4px;
    padding: 4px 6px;
    color: #bfbfc9;
}

QToolButton#newTabBtn:hover {
    background-color: #2b2a33;
    color: #fbfbfe;
}

/* Firefox Navigation Toolbar */
QToolBar {
    background-color: #2b2a33;
    border-bottom: 1px solid #1c1b22;
    padding: 4px 8px;
    spacing: 6px;
}

QToolButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 5px;
    color: #bfbfc9;
}

QToolButton:hover {
    background-color: #42414d;
    color: #fbfbfe;
}

QToolButton:pressed {
    background-color: #52525e;
}

/* Firefox AwesomeBar (Omnibox) */
QLineEdit#omnibox {
    background-color: #1c1b22;
    border: 1px solid #38383d;
    border-radius: 8px;
    color: #fbfbfe;
    padding: 6px 36px 6px 72px;
    font-size: 13px;
    selection-background-color: #0060df;
    selection-color: #ffffff;
}

QLineEdit#omnibox:focus {
    border: 1.5px solid #00ddff;
    background-color: #1c1b22;
}

/* Security Lock Badge inside Omnibox */
QPushButton#securityBadge {
    background-color: transparent;
    border: none;
    border-radius: 4px;
    padding: 2px 6px;
    color: #2ac3a2;
    font-weight: bold;
    font-size: 12px;
}

QPushButton#securityBadge:hover {
    background-color: rgba(42, 195, 162, 0.15);
}

/* DuckDuckGo / Privacy Grade Badge */
QPushButton#gradeBadge {
    background-color: rgba(0, 221, 255, 0.12);
    border: 1px solid rgba(0, 221, 255, 0.4);
    border-radius: 6px;
    padding: 1px 5px;
    color: #00ddff;
    font-weight: 800;
    font-size: 11px;
}

QPushButton#gradeBadge:hover {
    background-color: rgba(0, 221, 255, 0.25);
}

/* Shield Count Badge */
QPushButton#shieldBadge {
    background-color: #38383d;
    border: 1px solid #52525e;
    border-radius: 6px;
    padding: 2px 8px;
    color: #bfbfc9;
    font-weight: 600;
    font-size: 11px;
}

QPushButton#shieldBadge:hover {
    background-color: #42414d;
    border-color: #00ddff;
    color: #00ddff;
}

/* Tux Burner (Fire Button) */
QToolButton#fireBtn {
    background-color: rgba(255, 113, 57, 0.12);
    border: 1px solid rgba(255, 113, 57, 0.35);
    border-radius: 4px;
    padding: 4px;
    color: #ff7139;
}

QToolButton#fireBtn:hover {
    background-color: #ff7139;
    color: #1c1b22;
    border-color: #ff8f5a;
}

/* Tux Ghost Mode & Identity Rotation */
QToolButton#ghostBtn {
    border-radius: 4px;
    padding: 4px 6px;
    font-size: 12px;
}

QToolButton#ghostBtn[ghostActive="true"] {
    background-color: rgba(144, 89, 255, 0.22);
    border: 1px solid #9059ff;
    color: #d1b8ff;
    font-weight: bold;
}

QToolButton#ghostBtn[ghostActive="false"] {
    background-color: transparent;
    border: 1px solid transparent;
    color: #bfbfc9;
}

QToolButton#ghostBtn:hover {
    background-color: rgba(144, 89, 255, 0.3);
    color: #fff;
}

QToolButton#rotateIpBtn {
    background-color: rgba(0, 221, 255, 0.12);
    border: 1px solid rgba(0, 221, 255, 0.4);
    border-radius: 4px;
    padding: 4px 8px;
    color: #00ddff;
    font-size: 11px;
    font-weight: 700;
}

QToolButton#rotateIpBtn:hover {
    background-color: #00ddff;
    color: #1c1b22;
}

/* Bookmarks Bar */
QToolBar#bookmarksBar {
    background-color: #2b2a33;
    border-bottom: 1px solid #1c1b22;
    padding: 2px 10px;
    spacing: 4px;
    min-height: 28px;
}

QToolBar#bookmarksBar QToolButton {
    padding: 3px 8px;
    font-size: 12px;
    border-radius: 4px;
    color: #bfbfc9;
}

QToolBar#bookmarksBar QToolButton:hover {
    background-color: #42414d;
    color: #fbfbfe;
}

/* Status Bar */
QStatusBar {
    background-color: #1c1b22;
    border-top: 1px solid #2b2a33;
    color: #8f8f9d;
    font-size: 11px;
    padding: 2px 8px;
}

/* Find Bar */
QWidget#findBar {
    background-color: #2b2a33;
    border-top: 1px solid #38383d;
    padding: 6px 12px;
}

/* Menus & Popups */
QMenu {
    background-color: #2b2a33;
    border: 1px solid #38383d;
    border-radius: 6px;
    padding: 6px 0px;
}

QMenu::item {
    padding: 6px 24px 6px 16px;
    color: #fbfbfe;
}

QMenu::item:selected {
    background-color: #42414d;
    color: #00ddff;
}

QMenu::separator {
    height: 1px;
    background-color: #38383d;
    margin: 4px 8px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #1c1b22;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #42414d;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #00ddff;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""
