"""
TuxBrowser - Download Manager
Handles file downloads, progress monitoring, and safety verification.
"""

import os
import subprocess
from typing import List, Dict
from PySide6.QtWebEngineCore import QWebEngineDownloadRequest
from PySide6.QtCore import QObject, Signal, QStandardPaths
from PySide6.QtWidgets import QFileDialog, QMessageBox, QWidget


DANGEROUS_EXTENSIONS = {".sh", ".bin", ".exe", ".elf", ".deb", ".rpm", ".AppImage", ".run", ".cmd", ".bat"}


class TuxDownloadItem:
    def __init__(self, request: QWebEngineDownloadRequest):
        self.request = request
        self.filename = request.downloadFileName()
        self.path = request.downloadDirectory()
        self.total_bytes = request.totalBytes()
        self.received_bytes = request.receivedBytes()
        self.state = request.state()

        # Connect signals
        request.receivedBytesChanged.connect(self._on_progress)
        request.stateChanged.connect(self._on_state_changed)

    def _on_progress(self):
        self.received_bytes = self.request.receivedBytes()
        self.total_bytes = self.request.totalBytes()

    def _on_state_changed(self, state):
        self.state = state

    @property
    def progress_percent(self) -> int:
        if self.total_bytes > 0:
            return int((self.received_bytes / self.total_bytes) * 100)
        return 0


class TuxDownloadManager(QObject):
    download_started = Signal(TuxDownloadItem)
    download_finished = Signal(TuxDownloadItem)

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.parent_widget = parent
        self.active_downloads: List[TuxDownloadItem] = []
        
        # Default download directory (XDG Downloads or ~/Downloads)
        self.default_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        if not self.default_dir or not os.path.exists(self.default_dir):
            self.default_dir = os.path.expanduser("~/Downloads")
        os.makedirs(self.default_dir, exist_ok=True)

    def handle_download(self, item: QWebEngineDownloadRequest) -> None:
        filename = item.downloadFileName()
        ext = os.path.splitext(filename)[1].lower()

        # Security check: warn on executable files
        if ext in DANGEROUS_EXTENSIONS:
            if self.parent_widget:
                reply = QMessageBox.warning(
                    self.parent_widget,
                    "🛡️ Tux Shield: Предупреждение о безопасности",
                    f"Файл '{filename}' является исполняемым или установочным пакетом ({ext}).\n\nВы уверены, что хотите загрузить его?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    item.cancel()
                    return

        # Choose destination
        dest_path, _ = QFileDialog.getSaveFileName(
            self.parent_widget,
            "Сохранить файл как...",
            os.path.join(self.default_dir, filename)
        )

        if not dest_path:
            item.cancel()
            return

        item.setDownloadDirectory(os.path.dirname(dest_path))
        item.setDownloadFileName(os.path.basename(dest_path))
        item.accept()

        download_item = TuxDownloadItem(item)
        self.active_downloads.append(download_item)
        self.download_started.emit(download_item)

        item.stateChanged.connect(lambda state: self._check_finished(download_item, state))

    def _check_finished(self, item: TuxDownloadItem, state):
        if state == QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
            self.download_finished.emit(item)
        elif state == QWebEngineDownloadRequest.DownloadState.DownloadCancelled:
            if item in self.active_downloads:
                self.active_downloads.remove(item)

    @staticmethod
    def open_file_location(file_path: str):
        if os.path.exists(file_path):
            folder = os.path.dirname(file_path)
            subprocess.Popen(["xdg-open", folder])
