from __future__ import annotations

import threading
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from safewights import __app_name__, __version__
from safewights.config import DEFAULT_DOWNLOAD_DIR, DEFAULT_REPORTS_DIR
from safewights.downloader import (
    display_name_from_whoami,
    download_model,
    hf_login,
    hf_logout,
    hf_whoami,
)
from safewights.gui.theme import COLORS
from safewights.report import write_markdown_report
from safewights.scanner.engine import scan_path


class SafeWeightsApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{__app_name__}  ·  Model Intake Scanner  ·  v{__version__}")
        self.geometry("1000x720")
        self.minsize(820, 560)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color=COLORS["bg"])

        self._download_path: Path | None = None
        self._last_report_path: Path | None = None
        self._last_verdict: str | None = None
        self._busy = False
        self._hf_user: str | None = None
        self._advanced_open = False
        self._login_advanced_open = False
        self._device_login_url: str | None = None

        self._build()
        self.after(200, self._refresh_login_status)

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_scroll_body()
        self._build_action_bar()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=0, height=72)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", fill="y", padx=20, pady=10)
        ctk.CTkLabel(
            left,
            text="SafeWeights",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=COLORS["accent"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            left,
            text="Cybersecurity · HF intake · static scan · report",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["muted"],
        ).pack(anchor="w")

        self.verdict_label = ctk.CTkLabel(
            header,
            text="VERDICT: —",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["muted"],
        )
        self.verdict_label.pack(side="right", padx=20)

    def _build_scroll_body(self) -> None:
        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS["bg"],
            corner_radius=0,
            scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["button_hover"],
        )
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 4))
        self.scroll.grid_columnconfigure(0, weight=1)

        self._build_login_section(self.scroll)
        self._build_pull_section(self.scroll)
        self._build_scan_section(self.scroll)
        self._build_log_section(self.scroll)

    def _section(self, parent: ctk.CTkScrollableFrame, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(
            parent,
            fg_color=COLORS["panel"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        frame.pack(fill="x", pady=(0, 10), padx=4)
        ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=14, pady=(12, 6))
        return frame

    def _path_row(
        self,
        parent: ctk.CTkFrame,
        label: str,
        browse_cmd,
        *,
        placeholder: str = "",
        initial: str = "",
    ) -> ctk.CTkEntry:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(row, text=label, width=110, anchor="w", text_color=COLORS["muted"]).pack(side="left")
        entry = ctk.CTkEntry(
            row,
            height=32,
            placeholder_text=placeholder,
            fg_color=COLORS["panel_alt"],
            border_color=COLORS["border"],
        )
        if initial:
            entry.insert(0, initial)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(
            row,
            text="Browse",
            width=78,
            height=32,
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            command=browse_cmd,
        ).pack(side="left")
        return entry

    def _build_login_section(self, parent: ctk.CTkScrollableFrame) -> None:
        box = self._section(parent, "0  ·  Hugging Face login")

        status_row = ctk.CTkFrame(box, fg_color="transparent")
        status_row.pack(fill="x", padx=14, pady=(0, 6))
        self.login_status = ctk.CTkLabel(
            status_row,
            text="Status: checking…",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.login_status.pack(side="left", fill="x", expand=True)

        hint = ctk.CTkLabel(
            box,
            text=(
                "Sign in with the same browser / device link flow as "
                "`hf auth login` (opens a Hugging Face URL; no token paste required)."
            ),
            font=ctk.CTkFont(size=11),
            text_color=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        )
        hint.pack(fill="x", padx=14, pady=(0, 4))

        self.login_link_label = ctk.CTkLabel(
            box,
            text="Login URL: —",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["accent"],
            wraplength=900,
            justify="left",
            anchor="w",
            cursor="hand2",
        )
        self.login_link_label.pack(fill="x", padx=14, pady=(0, 2))
        self.login_link_label.bind("<Button-1>", self._open_login_url)

        self.login_code_label = ctk.CTkLabel(
            box,
            text="Device code: —",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text"],
            anchor="w",
        )
        self.login_code_label.pack(fill="x", padx=14, pady=(0, 6))

        btn_row = ctk.CTkFrame(box, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(6, 4))
        ctk.CTkButton(
            btn_row,
            text="Login with Hugging Face",
            width=200,
            height=34,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent"],
            text_color="#001018",
            font=ctk.CTkFont(weight="bold"),
            command=self._on_login,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Logout",
            width=110,
            height=34,
            fg_color=COLORS["danger_btn"],
            hover_color=COLORS["danger_hover"],
            command=self._on_logout,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Refresh status",
            width=120,
            height=34,
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            command=self._refresh_login_status,
        ).pack(side="left")

        # Advanced: air-gapped token paste (hidden by default)
        adv_hdr = ctk.CTkFrame(box, fg_color="transparent")
        adv_hdr.pack(fill="x", padx=14, pady=(4, 0))
        self.login_adv_toggle = ctk.CTkButton(
            adv_hdr,
            text="▸ Advanced (paste token)",
            width=220,
            height=28,
            fg_color="transparent",
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            anchor="w",
            command=self._toggle_login_advanced,
        )
        self.login_adv_toggle.pack(side="left")

        self.login_advanced_frame = ctk.CTkFrame(box, fg_color=COLORS["panel_alt"], corner_radius=8)
        ctk.CTkLabel(
            self.login_advanced_frame,
            text="Air-gapped fallback only. Prefer Login with Hugging Face above.",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 2))
        row = ctk.CTkFrame(self.login_advanced_frame, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkLabel(row, text="Access token", width=110, anchor="w", text_color=COLORS["muted"]).pack(
            side="left"
        )
        self.hf_token = ctk.CTkEntry(
            row,
            placeholder_text="hf_…  (stored in HF cache — never written to reports)",
            show="*",
            height=30,
            fg_color=COLORS["bg"],
            border_color=COLORS["border"],
        )
        self.hf_token.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(
            row,
            text="Sign in with token",
            width=140,
            height=30,
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            command=self._on_token_login,
        ).pack(side="left")
        ctk.CTkFrame(box, fg_color="transparent", height=8).pack()

    def _build_pull_section(self, parent: ctk.CTkScrollableFrame) -> None:
        box = self._section(parent, "1  ·  Pull from Hugging Face")

        row1 = ctk.CTkFrame(box, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(row1, text="Model ID", width=110, anchor="w", text_color=COLORS["muted"]).pack(
            side="left"
        )
        self.model_id = ctk.CTkEntry(
            row1,
            placeholder_text="example: google/gemma-2-9b-it",
            height=32,
            fg_color=COLORS["panel_alt"],
            border_color=COLORS["border"],
        )
        self.model_id.pack(side="left", fill="x", expand=True)

        self.download_dir = self._path_row(
            box,
            "Download to",
            self._browse_download,
            initial=str(DEFAULT_DOWNLOAD_DIR),
        )

        # Collapsible advanced: one-off token override
        adv_hdr = ctk.CTkFrame(box, fg_color="transparent")
        adv_hdr.pack(fill="x", padx=14, pady=(6, 0))
        self.adv_toggle = ctk.CTkButton(
            adv_hdr,
            text="▸ Advanced (one-off token override)",
            width=280,
            height=28,
            fg_color="transparent",
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            anchor="w",
            command=self._toggle_advanced,
        )
        self.adv_toggle.pack(side="left")

        self.advanced_frame = ctk.CTkFrame(box, fg_color=COLORS["panel_alt"], corner_radius=8)
        # starts collapsed — not packed
        ctk.CTkLabel(
            self.advanced_frame,
            text="Optional: use a different token for this Pull only (does not change saved login).",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 2))
        row_ov = ctk.CTkFrame(self.advanced_frame, fg_color="transparent")
        row_ov.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(row_ov, text="Override token", width=110, anchor="w", text_color=COLORS["muted"]).pack(
            side="left"
        )
        self.hf_token_override = ctk.CTkEntry(
            row_ov,
            placeholder_text="leave blank to use logged-in session",
            show="*",
            height=30,
            fg_color=COLORS["bg"],
            border_color=COLORS["border"],
        )
        self.hf_token_override.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            box,
            text="Pull Model",
            height=36,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent"],
            text_color="#001018",
            font=ctk.CTkFont(weight="bold"),
            command=self._on_pull,
        ).pack(fill="x", padx=14, pady=(8, 12))

    def _build_scan_section(self, parent: ctk.CTkScrollableFrame) -> None:
        box = self._section(parent, "2  ·  Scan target & destinations")

        self.scan_path = self._path_row(box, "Model folder", self._browse_scan)
        self.reports_dir = self._path_row(
            box,
            "Reports",
            lambda: self._browse_into(self.reports_dir),
            initial=str(DEFAULT_REPORTS_DIR),
        )

        analyst_row = ctk.CTkFrame(box, fg_color="transparent")
        analyst_row.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(analyst_row, text="Analyst", width=110, anchor="w", text_color=COLORS["muted"]).pack(
            side="left"
        )
        self.analyst = ctk.CTkEntry(
            analyst_row,
            placeholder_text="your name / initials",
            height=32,
            fg_color=COLORS["panel_alt"],
            border_color=COLORS["border"],
        )
        self.analyst.pack(side="left", fill="x", expand=True)

        ctk.CTkFrame(box, fg_color="transparent", height=8).pack()

    def _build_log_section(self, parent: ctk.CTkScrollableFrame) -> None:
        box = self._section(parent, "Activity log")
        # Modest fixed height so primary controls stay reachable; scroll body covers overflow
        self.log = ctk.CTkTextbox(
            box,
            height=140,
            fg_color=COLORS["panel_alt"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.log.pack(fill="x", expand=False, padx=14, pady=(0, 12))
        self._append_log("Ready. Sign in (if needed), enter a model ID, pull, then scan.")

    def _build_action_bar(self) -> None:
        bottom = ctk.CTkFrame(
            self,
            fg_color=COLORS["panel"],
            corner_radius=0,
            border_width=1,
            border_color=COLORS["border"],
        )
        bottom.grid(row=2, column=0, sticky="ew")

        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(
            btn_row,
            text="Run Scan & Generate Report",
            height=40,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent"],
            text_color="#001018",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._on_scan,
        ).pack(side="left", fill="x", expand=True)

    def _toggle_advanced(self) -> None:
        self._advanced_open = not self._advanced_open
        if self._advanced_open:
            self.advanced_frame.pack(fill="x", padx=14, pady=(4, 0))
            self.adv_toggle.configure(text="▾ Advanced (one-off token override)")
        else:
            self.advanced_frame.pack_forget()
            self.adv_toggle.configure(text="▸ Advanced (one-off token override)")

    def _toggle_login_advanced(self) -> None:
        self._login_advanced_open = not self._login_advanced_open
        if self._login_advanced_open:
            self.login_advanced_frame.pack(fill="x", padx=14, pady=(4, 0))
            self.login_adv_toggle.configure(text="▾ Advanced (paste token)")
        else:
            self.login_advanced_frame.pack_forget()
            self.login_adv_toggle.configure(text="▸ Advanced (paste token)")

    def _set_login_status(self, signed_in: bool, user: str | None = None) -> None:
        self._hf_user = user if signed_in else None
        if signed_in and user:
            self.login_status.configure(
                text=f"Status: Signed in as {user}",
                text_color=COLORS["ok"],
            )
        elif signed_in:
            self.login_status.configure(text="Status: Signed in", text_color=COLORS["ok"])
        else:
            self.login_status.configure(text="Status: Not signed in", text_color=COLORS["warn"])

    def _set_device_login_ui(self, url: str, user_code: str) -> None:
        self._device_login_url = url or None
        self.login_link_label.configure(text=f"Login URL: {url or '—'}")
        self.login_code_label.configure(text=f"Device code: {user_code or '—'}")

    def _clear_device_login_ui(self) -> None:
        self._device_login_url = None
        self.login_link_label.configure(text="Login URL: —")
        self.login_code_label.configure(text="Device code: —")

    def _open_login_url(self, _event=None) -> None:
        if self._device_login_url:
            webbrowser.open(self._device_login_url)

    def _refresh_login_status(self) -> None:
        def worker() -> None:
            try:
                info = hf_whoami()
                name = display_name_from_whoami(info)
                self.after(0, self._set_login_status, bool(info), name)
            except Exception as exc:  # noqa: BLE001
                def fail() -> None:
                    self._set_login_status(False)
                    self._append_log(f"Login status check failed: {exc}")

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _on_login(self) -> None:
        """Start HF CLI-equivalent device / browser login (no token paste)."""
        if self._busy:
            return

        self._set_busy(True)
        self._append_log("Starting Hugging Face browser / device login…")

        def on_device_info(info: dict) -> None:
            url = str(info.get("verification_uri_complete") or info.get("verification_uri") or "")
            code = str(info.get("user_code") or "")

            def ui() -> None:
                self._set_device_login_ui(url, code)
                if url:
                    self._append_log(f"Open this URL to authorize: {url}")
                if code:
                    self._append_log(f"Device / user code: {code}")
                self._append_log("Waiting for authorization in the browser…")

            self.after(0, ui)

        def worker() -> None:
            try:
                info = hf_login(
                    on_device_info=on_device_info,
                    open_browser=True,
                )
                name = display_name_from_whoami(info) or "user"

                def done() -> None:
                    self._clear_device_login_ui()
                    self._set_login_status(True, name)
                    self._append_log(f"Signed in as {name}")
                    self._set_busy(False)

                self.after(0, done)
            except Exception as exc:  # noqa: BLE001
                def fail() -> None:
                    self._append_log(f"Login failed: {exc}")
                    self._set_busy(False)
                    messagebox.showerror("Login failed", str(exc))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _on_token_login(self) -> None:
        """Advanced air-gapped fallback: paste token."""
        if self._busy:
            return
        token = self.hf_token.get().strip()
        if not token:
            messagebox.showwarning("Missing token", "Paste a Hugging Face access token, or use Login with Hugging Face.")
            return

        self._set_busy(True)
        self._append_log("Signing in with pasted token (advanced)…")

        def worker() -> None:
            try:
                info = hf_login(token)
                name = display_name_from_whoami(info) or "user"

                def done() -> None:
                    self.hf_token.delete(0, "end")
                    self._set_login_status(True, name)
                    self._append_log(f"Signed in as {name}")
                    self._set_busy(False)

                self.after(0, done)
            except Exception as exc:  # noqa: BLE001
                def fail() -> None:
                    self._append_log(f"Login failed: {exc}")
                    self._set_busy(False)
                    messagebox.showerror("Login failed", str(exc))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _on_logout(self) -> None:
        if self._busy:
            return
        self._set_busy(True)

        def worker() -> None:
            try:
                hf_logout()

                def done() -> None:
                    self._clear_device_login_ui()
                    self._set_login_status(False)
                    self._append_log("Signed out of Hugging Face.")
                    self._set_busy(False)

                self.after(0, done)
            except Exception as exc:  # noqa: BLE001
                def fail() -> None:
                    self._append_log(f"Logout failed: {exc}")
                    self._set_busy(False)
                    messagebox.showerror("Logout failed", str(exc))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _append_log(self, msg: str) -> None:
        # Never echo tokens if a user pastes one into the wrong field by mistake.
        # Login URLs / device codes are safe to show (same as hf auth login).
        lowered = msg.lower()
        looks_like_secret = (
            ("hf_" in lowered and "http" not in lowered)
            or "token=" in lowered
            or "authorization: bearer" in lowered
        )
        if looks_like_secret:
            msg = "[redacted — credentials are not written to the activity log]"
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{stamp}] {msg}\n")
        self.log.see("end")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy

    def _browse_download(self) -> None:
        path = filedialog.askdirectory(title="Select download folder")
        if path:
            self.download_dir.delete(0, "end")
            self.download_dir.insert(0, path)

    def _browse_scan(self) -> None:
        path = filedialog.askdirectory(title="Select model folder to scan")
        if path:
            self.scan_path.delete(0, "end")
            self.scan_path.insert(0, path)

    def _browse_into(self, entry: ctk.CTkEntry) -> None:
        path = filedialog.askdirectory()
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _on_pull(self) -> None:
        if self._busy:
            return
        model_id = self.model_id.get().strip()
        dest = self.download_dir.get().strip()
        if not model_id:
            messagebox.showwarning("Missing model ID", "Enter a Hugging Face model ID (org/name).")
            return
        if not dest:
            messagebox.showwarning("Missing folder", "Choose a download folder.")
            return

        # Optional one-off override; otherwise downloader uses logged-in session
        override = self.hf_token_override.get().strip() if self._advanced_open else ""
        token = override or None

        self._set_busy(True)
        self._append_log(f"Pull requested for {model_id}")

        def worker() -> None:
            try:
                path = download_model(
                    model_id, Path(dest), token=token, progress=lambda m: self.after(0, self._append_log, m)
                )

                def done() -> None:
                    self._download_path = path
                    self.scan_path.delete(0, "end")
                    self.scan_path.insert(0, str(path))
                    self._append_log("Pull finished. Scan path updated.")
                    self._set_busy(False)

                self.after(0, done)
            except Exception as exc:  # noqa: BLE001
                err = f"Pull failed: {exc}"
                tb = traceback.format_exc()

                def fail() -> None:
                    self._append_log(err)
                    self._append_log(tb)
                    self._set_busy(False)
                    messagebox.showerror("Download failed", str(exc))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan(self) -> None:
        if self._busy:
            return
        target = self.scan_path.get().strip()
        if not target:
            messagebox.showwarning("Missing path", "Select the local model folder to scan.")
            return
        reports = self.reports_dir.get().strip() or str(DEFAULT_REPORTS_DIR)
        model_id = self.model_id.get().strip() or Path(target).name
        analyst = self.analyst.get().strip()

        self._set_busy(True)
        self._append_log(f"Scanning {target} …")
        self.verdict_label.configure(text="VERDICT: scanning…", text_color=COLORS["warn"])

        def worker() -> None:
            try:
                report = scan_path(Path(target), model_id=model_id)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_id = model_id.replace("/", "__")
                out = Path(reports) / f"SafeWeights_{safe_id}_{stamp}.md"
                write_markdown_report(report, out, analyst=analyst)
                counts = report.counts_by_severity()

                def done() -> None:
                    self._last_report_path = out
                    self._last_verdict = report.verdict
                    color = COLORS["ok"] if report.verdict == "PASS" else COLORS["bad"]
                    self.verdict_label.configure(text=f"VERDICT: {report.verdict}", text_color=color)
                    self._append_log(f"Verdict: {report.verdict}")
                    self._append_log("Findings — " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
                    self._append_log(f"Report written: {out}")
                    self._set_busy(False)
                    messagebox.showinfo("Scan complete", f"Verdict: {report.verdict}\n\nReport:\n{out}")

                self.after(0, done)
            except Exception as exc:  # noqa: BLE001

                def fail() -> None:
                    self._append_log(f"Scan failed: {exc}")
                    self._append_log(traceback.format_exc())
                    self.verdict_label.configure(text="VERDICT: ERROR", text_color=COLORS["bad"])
                    self._set_busy(False)
                    messagebox.showerror("Scan failed", str(exc))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()


def run_app() -> None:
    app = SafeWeightsApp()
    app.mainloop()
