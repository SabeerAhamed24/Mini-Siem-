import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import hashlib
from datetime import datetime

from ir_guidance import get_guidance  # uses your existing IR guidance file

# ===== ANALYTICS IMPORTS ADDED =====
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ===========================
# FIXED DB PATH
# ===========================
DB_DIR = r"C:\Users\sabee\OneDrive\Desktop\project new\code"
DB_PATH = os.path.join(DB_DIR, "siem_logs.db")
AUTO_REFRESH_MS = 3000  # 3 seconds

# Ensure folder exists
os.makedirs(DB_DIR, exist_ok=True)

# Optional: if report.py exists, enable PDF generation
REPORT_AVAILABLE = False
try:
    from report import generate_pdf_report  # your report.py function
    REPORT_AVAILABLE = True
except Exception:
    REPORT_AVAILABLE = False


# ===========================
# DB helpers (users table + make sure core tables exist)
# ===========================
def ensure_users_table():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()

    # Ensure all required tables exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            log_type TEXT,
            message TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS endpoints(
            source TEXT PRIMARY KEY,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_ip TEXT,
            os TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


# ===== ANALYTICS DB HELPERS ADDED =====
def get_severity_counts():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        SELECT severity, COUNT(*)
        FROM logs
        GROUP BY severity
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_logs_over_time():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute_slot, COUNT(*)
        FROM logs
        GROUP BY minute_slot
        ORDER BY minute_slot ASC
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_top_sources(limit=5):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        SELECT source, COUNT(*)
        FROM logs
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


# ===========================
# LOGIN / CREATE ACCOUNT UI
# ===========================
class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Clavis Solutions - Mini SIEM Login")
        self.geometry("420x320")
        self.resizable(False, False)

        ensure_users_table()

        tk.Label(self, text="Clavis Solutions", font=("Segoe UI", 18, "bold")).pack(pady=(18, 2))
        tk.Label(self, text="Mini SIEM Dashboard", font=("Segoe UI", 11)).pack(pady=(0, 18))

        frame = tk.Frame(self)
        frame.pack(pady=10)

        tk.Label(frame, text="Username", font=("Segoe UI", 10)).grid(row=0, column=0, sticky="e", padx=8, pady=8)
        tk.Label(frame, text="Password", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="e", padx=8, pady=8)

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self.username_entry = ttk.Entry(frame, textvariable=self.username_var, width=26)
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var, width=26, show="*")

        self.username_entry.grid(row=0, column=1, pady=8)
        self.password_entry.grid(row=1, column=1, pady=8)

        btns = tk.Frame(self)
        btns.pack(pady=10)

        ttk.Button(btns, text="Login", width=16, command=self.login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Create Account", width=16, command=self.open_create_account).grid(row=0, column=1, padx=6)

        self.bind("<Return>", lambda e: self.login())

    def login(self):
        u = self.username_var.get().strip()
        p = self.password_var.get().strip()

        if not u or not p:
            messagebox.showerror("Login Error", "Please enter both username and password.")
            return

        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (u,))
        row = cur.fetchone()
        conn.close()

        if row and row[0] == hash_password(p):
            self.destroy()
            app = MiniSIEMDashboard(username=u)
            app.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def open_create_account(self):
        CreateAccountWindow(parent=self)


class CreateAccountWindow(tk.Toplevel):
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Clavis Solutions - Create Account")
        self.geometry("420x260")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="Create Account", font=("Segoe UI", 14, "bold")).pack(pady=(14, 10))

        frame = tk.Frame(self)
        frame.pack(pady=6)

        tk.Label(frame, text="New Username", font=("Segoe UI", 10)).grid(row=0, column=0, sticky="e", padx=8, pady=8)
        tk.Label(frame, text="New Password", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="e", padx=8, pady=8)

        self.new_user_var = tk.StringVar()
        self.new_pass_var = tk.StringVar()

        ttk.Entry(frame, textvariable=self.new_user_var, width=26).grid(row=0, column=1, pady=8)
        ttk.Entry(frame, textvariable=self.new_pass_var, width=26, show="*").grid(row=1, column=1, pady=8)

        ttk.Button(self, text="Create", width=18, command=self.create).pack(pady=14)

    def create(self):
        u = self.new_user_var.get().strip()
        p = self.new_pass_var.get().strip()

        if not u or not p:
            messagebox.showerror("Error", "Username and password are required.")
            return

        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (u, hash_password(p)))
            conn.commit()
            messagebox.showinfo("Success", "Account created successfully. You can login now.")
            self.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists. Try another username.")
        finally:
            conn.close()


# ===========================
# MAIN DASHBOARD
# ===========================
class MiniSIEMDashboard(tk.Tk):
    def __init__(self, username=""):
        super().__init__()
        self.title(f"Clavis Solutions - Mini SIEM Dashboard (User: {username})")
        self.geometry("1300x720")
        self.minsize(1150, 650)

        # DB
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.conn.cursor()

        # state
        self.current_view = "logs"

        # IMPORTANT: initialize popup tracking to current latest HIGH,
        # so old HIGH alerts don't keep popping
        self.last_seen_high_id = self._get_latest_high_id()

        # Layout
        self._build_layout()
        self._build_left_menu()
        self._build_views()

        # Default view
        self.show_view("logs")

        # Start auto refresh
        self.after(AUTO_REFRESH_MS, self.auto_refresh)

    # ---------------- UI BUILD ----------------
    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = tk.Frame(self, width=220, bg="#1f2937")
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)

        self.main = tk.Frame(self, bg="#0b1220")
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_rowconfigure(0, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

    def _build_left_menu(self):
        title = tk.Label(
            self.sidebar,
            text="CLAVIS SIEM",
            fg="white",
            bg="#1f2937",
            font=("Segoe UI", 16, "bold"),
            pady=15
        )
        title.pack(fill="x")

        btn_style = {
            "font": ("Segoe UI", 11),
            "fg": "white",
            "bg": "#111827",
            "activebackground": "#374151",
            "activeforeground": "white",
            "bd": 0,
            "relief": "flat",
            "pady": 10
        }

        tk.Button(self.sidebar, text="Logs", command=lambda: self.show_view("logs"), **btn_style)\
            .pack(fill="x", padx=12, pady=6)
        tk.Button(self.sidebar, text="Connected Devices", command=lambda: self.show_view("devices"), **btn_style)\
            .pack(fill="x", padx=12, pady=6)
        tk.Button(self.sidebar, text="Alerts", command=lambda: self.show_view("alerts"), **btn_style)\
            .pack(fill="x", padx=12, pady=6)

        # ===== ANALYTICS BUTTON ADDED BACK =====
        tk.Button(self.sidebar, text="Analytics", command=lambda: self.show_view("analytics"), **btn_style)\
            .pack(fill="x", padx=12, pady=6)

        tk.Label(self.sidebar, text="", bg="#1f2937").pack(pady=5)

        if REPORT_AVAILABLE:
            tk.Button(self.sidebar, text="Generate Report (PDF)", command=self.generate_report, **btn_style)\
                .pack(fill="x", padx=12, pady=6)
        else:
            tk.Button(self.sidebar, text="Generate Report (PDF)", command=self.report_missing, **btn_style)\
                .pack(fill="x", padx=12, pady=6)

        tk.Button(self.sidebar, text="Refresh", command=self.refresh_current_view, **btn_style)\
            .pack(fill="x", padx=12, pady=6)
        tk.Button(self.sidebar, text="Exit", command=self.on_exit, **btn_style)\
            .pack(fill="x", padx=12, pady=6)

        footer = tk.Label(
            self.sidebar,
            text="Clavis Solutions | v1.1",
            fg="#9ca3af",
            bg="#1f2937",
            font=("Segoe UI", 9)
        )
        footer.pack(side="bottom", pady=12)

    def _build_views(self):
        self.views = {}

        # Logs view
        self.views["logs"] = tk.Frame(self.main, bg="#0b1220")
        self._build_logs_view(self.views["logs"])

        # Devices view
        self.views["devices"] = tk.Frame(self.main, bg="#0b1220")
        self._build_devices_view(self.views["devices"])

        # Alerts view
        self.views["alerts"] = tk.Frame(self.main, bg="#0b1220")
        self._build_alerts_view(self.views["alerts"])

        # ===== ANALYTICS VIEW ADDED BACK =====
        self.views["analytics"] = tk.Frame(self.main, bg="#0b1220")
        self._build_analytics_view(self.views["analytics"])

        for v in self.views.values():
            v.grid(row=0, column=0, sticky="nsew")

    # ---------------- VIEW SWITCH ----------------
    def show_view(self, name):
        self.current_view = name
        self.views[name].tkraise()
        self.refresh_current_view()

    def refresh_current_view(self):
        if self.current_view == "logs":
            self.load_logs()
        elif self.current_view == "devices":
            self.load_devices()
        elif self.current_view == "alerts":
            self.load_alerts()
        elif self.current_view == "analytics":
            self.load_analytics()

    # ---------------- LOGS VIEW + GUIDANCE PANEL ----------------
    def _build_logs_view(self, parent):
        # Split area: left table + right guidance
        container = tk.Frame(parent, bg="#0b1220")
        container.pack(fill="both", expand=True)

        left = tk.Frame(container, bg="#0b1220")
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(container, bg="#111827", width=420)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        header = tk.Frame(left, bg="#0b1220")
        header.pack(fill="x", pady=10, padx=12)
        tk.Label(header, text="Logs", fg="white", bg="#0b1220",
                 font=("Segoe UI", 18, "bold")).pack(side="left")

        # Filters
        filters = tk.Frame(left, bg="#0b1220")
        filters.pack(fill="x", padx=12)

        tk.Label(filters, text="Severity:", fg="white", bg="#0b1220").pack(side="left")
        self.sev_var = tk.StringVar(value="ALL")
        self.sev_combo = ttk.Combobox(filters, textvariable=self.sev_var,
                                      values=["ALL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                      width=10, state="readonly")
        self.sev_combo.pack(side="left", padx=6)

        tk.Label(filters, text="Type:", fg="white", bg="#0b1220").pack(side="left", padx=(12, 0))
        self.type_var = tk.StringVar(value="ALL")
        self.type_combo = ttk.Combobox(filters, textvariable=self.type_var,
                                       values=["ALL", "FIM", "PROCESS", "USB_INSERT", "USB_ALLOWED", "USB_BLOCKED",
                                               "ANOMALY", "CORR", "HEARTBEAT", "USB_SCAN"],
                                       width=14, state="readonly")
        self.type_combo.pack(side="left", padx=6)

        tk.Label(filters, text="Source:", fg="white", bg="#0b1220").pack(side="left", padx=(12, 0))
        self.source_var = tk.StringVar(value="")
        self.source_entry = ttk.Entry(filters, textvariable=self.source_var, width=18)
        self.source_entry.pack(side="left", padx=6)

        tk.Label(filters, text="Search:", fg="white", bg="#0b1220").pack(side="left", padx=(12, 0))
        self.search_var = tk.StringVar(value="")
        self.search_entry = ttk.Entry(filters, textvariable=self.search_var, width=24)
        self.search_entry.pack(side="left", padx=6)

        ttk.Button(filters, text="Apply", command=self.load_logs).pack(side="left", padx=10)
        ttk.Button(filters, text="Clear", command=self.clear_log_filters).pack(side="left")

        # Tree
        table_frame = tk.Frame(left, bg="#0b1220")
        table_frame.pack(fill="both", expand=True, padx=12, pady=12)

        cols = ("id", "timestamp", "source", "type", "severity", "message")
        self.logs_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=18)
        for c in cols:
            self.logs_tree.heading(c, text=c.upper())
        self.logs_tree.column("id", width=60, anchor="center")
        self.logs_tree.column("timestamp", width=170, anchor="center")
        self.logs_tree.column("source", width=150)
        self.logs_tree.column("type", width=120, anchor="center")
        self.logs_tree.column("severity", width=90, anchor="center")
        self.logs_tree.column("message", width=520)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=yscroll.set)
        self.logs_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        # Double click: show full message
        self.logs_tree.bind("<Double-1>", self.on_log_double_click)

        # Single click: show guidance panel
        self.logs_tree.bind("<<TreeviewSelect>>", self.on_log_select_show_guidance)

        hint = tk.Label(left, text="Tip: Double-click a row to view full message. Single-click to see guidance.",
                        fg="#9ca3af", bg="#0b1220", font=("Segoe UI", 9))
        hint.pack(anchor="w", padx=14, pady=(0, 10))

        # -------- Guidance Panel (Right) --------
        tk.Label(right, text="Incident Response Guidance", fg="white", bg="#111827",
                 font=("Segoe UI", 13, "bold")).pack(pady=(12, 6))

        self.guidance_box = tk.Text(right, wrap="word", height=30, bg="#0b1220", fg="white")
        self.guidance_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.guidance_box.insert("1.0", "Select a HIGH / MEDIUM / LOW log to view IR guidance here.")
        self.guidance_box.config(state="disabled")

    def on_log_select_show_guidance(self, event):
        item = self.logs_tree.focus()
        if not item:
            return
        values = self.logs_tree.item(item, "values")
        if not values:
            return

        _id, ts, src, lt, sev, msg = values
        guidance = get_guidance(str(sev).upper())

        text = (
            f"Clavis Solutions - Incident Response\n\n"
            f"Log ID: {_id}\n"
            f"Time: {ts}\n"
            f"Source: {src}\n"
            f"Type: {lt}\n"
            f"Severity: {sev}\n\n"
            f"Message:\n{msg}\n\n"
            f"----- Guidance -----\n"
            f"{guidance}"
        )

        self.guidance_box.config(state="normal")
        self.guidance_box.delete("1.0", tk.END)
        self.guidance_box.insert("1.0", text)
        self.guidance_box.config(state="disabled")

    def clear_log_filters(self):
        self.sev_var.set("ALL")
        self.type_var.set("ALL")
        self.source_var.set("")
        self.search_var.set("")
        self.load_logs()

    def load_logs(self):
        if not os.path.exists(DB_PATH):
            messagebox.showerror("DB not found", f"Database '{DB_PATH}' not found.")
            return

        sev = self.sev_var.get().strip().upper()
        lt = self.type_var.get().strip().upper()
        src = self.source_var.get().strip()
        q = self.search_var.get().strip()

        sql = "SELECT id, timestamp, source, log_type, severity, message FROM logs WHERE 1=1"
        params = []

        if sev != "ALL":
            sql += " AND severity = ?"
            params.append(sev)

        if lt != "ALL":
            sql += " AND log_type = ?"
            params.append(lt)

        if src:
            sql += " AND source LIKE ?"
            params.append(f"%{src}%")

        if q:
            sql += " AND message LIKE ?"
            params.append(f"%{q}%")

        sql += " ORDER BY id DESC LIMIT 500"

        self.cursor.execute(sql, params)
        rows = self.cursor.fetchall()

        self._tree_clear(self.logs_tree)
        for r in rows:
            self.logs_tree.insert("", "end", values=r)

    def on_log_double_click(self, event):
        item = self.logs_tree.focus()
        if not item:
            return
        values = self.logs_tree.item(item, "values")
        if not values:
            return
        _id, ts, src, lt, sev, msg = values
        messagebox.showinfo(
            f"Log #{_id}",
            f"Time: {ts}\nSource: {src}\nType: {lt}\nSeverity: {sev}\n\nMessage:\n{msg}"
        )

    # ---------------- DEVICES VIEW ----------------
    def _build_devices_view(self, parent):
        header = tk.Frame(parent, bg="#0b1220")
        header.pack(fill="x", pady=10, padx=12)
        tk.Label(header, text="Connected Devices", fg="white", bg="#0b1220",
                 font=("Segoe UI", 18, "bold")).pack(side="left")

        sub = tk.Label(parent, text="Shows endpoints sending heartbeat/logs (based on endpoints table).",
                       fg="#9ca3af", bg="#0b1220", font=("Segoe UI", 10))
        sub.pack(anchor="w", padx=14, pady=(0, 10))

        table_frame = tk.Frame(parent, bg="#0b1220")
        table_frame.pack(fill="both", expand=True, padx=12, pady=12)

        cols = ("source", "last_seen", "last_ip", "os", "status")
        self.devices_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=18)
        for c in cols:
            self.devices_tree.heading(c, text=c.upper())

        self.devices_tree.column("source", width=220)
        self.devices_tree.column("last_seen", width=200, anchor="center")
        self.devices_tree.column("last_ip", width=150, anchor="center")
        self.devices_tree.column("os", width=120, anchor="center")
        self.devices_tree.column("status", width=120, anchor="center")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=yscroll.set)

        self.devices_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

    def load_devices(self):
        self.cursor.execute("""
            SELECT source, last_seen, last_ip, os
            FROM endpoints
            ORDER BY last_seen DESC
            LIMIT 200
        """)
        rows = self.cursor.fetchall()

        self._tree_clear(self.devices_tree)
        for source, last_seen, ip, os_name in rows:
            status = self._calc_status(last_seen, online_seconds=15)
            self.devices_tree.insert("", "end", values=(source, last_seen, ip, os_name, status))

    def _calc_status(self, last_seen_str, online_seconds=15):
        try:
            last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            delta = (datetime.now() - last_seen).total_seconds()
            return "ONLINE" if delta <= online_seconds else "OFFLINE"
        except Exception:
            return "UNKNOWN"

    # ---------------- ALERTS VIEW ----------------
    def _build_alerts_view(self, parent):
        header = tk.Frame(parent, bg="#0b1220")
        header.pack(fill="x", pady=10, padx=12)
        tk.Label(header, text="Alerts", fg="white", bg="#0b1220", font=("Segoe UI", 18, "bold")).pack(side="left")

        sub = tk.Label(parent, text="Shows non-INFO logs (includes correlation alerts). Double-click to view details.",
                       fg="#9ca3af", bg="#0b1220", font=("Segoe UI", 10))
        sub.pack(anchor="w", padx=14, pady=(0, 10))

        table_frame = tk.Frame(parent, bg="#0b1220")
        table_frame.pack(fill="both", expand=True, padx=12, pady=12)

        cols = ("id", "timestamp", "source", "type", "severity", "message")
        self.alerts_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=18)
        for c in cols:
            self.alerts_tree.heading(c, text=c.upper())

        self.alerts_tree.column("id", width=60, anchor="center")
        self.alerts_tree.column("timestamp", width=170, anchor="center")
        self.alerts_tree.column("source", width=150)
        self.alerts_tree.column("type", width=120, anchor="center")
        self.alerts_tree.column("severity", width=90, anchor="center")
        self.alerts_tree.column("message", width=520)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=yscroll.set)

        self.alerts_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.alerts_tree.bind("<Double-1>", self.on_alert_double_click)

        # Popup toggle
        bottom = tk.Frame(parent, bg="#0b1220")
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        self.popup_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            bottom,
            text="Popup on new HIGH alerts",
            variable=self.popup_var,
            fg="white", bg="#0b1220", activebackground="#0b1220",
            selectcolor="#0b1220"
        ).pack(side="left")

    def load_alerts(self):
        self.cursor.execute("""
            SELECT id, timestamp, source, log_type, severity, message
            FROM logs
            WHERE severity != 'INFO'
            ORDER BY id DESC
            LIMIT 300
        """)
        rows = self.cursor.fetchall()

        self._tree_clear(self.alerts_tree)
        for r in rows:
            self.alerts_tree.insert("", "end", values=r)

    def on_alert_double_click(self, event):
        item = self.alerts_tree.focus()
        if not item:
            return
        values = self.alerts_tree.item(item, "values")
        if not values:
            return
        _id, ts, src, lt, sev, msg = values
        messagebox.showwarning(
            f"Alert #{_id} [{sev}]",
            f"Time: {ts}\nSource: {src}\nType: {lt}\nSeverity: {sev}\n\nMessage:\n{msg}"
        )

    # ---------------- ANALYTICS VIEW ADDED BACK ----------------
    def _build_analytics_view(self, parent):
        header = tk.Frame(parent, bg="#0b1220")
        header.pack(fill="x", pady=10, padx=12)

        tk.Label(
            header,
            text="Analytics Dashboard",
            fg="white",
            bg="#0b1220",
            font=("Segoe UI", 18, "bold")
        ).pack(side="left")

        self.analytics_container = tk.Frame(parent, bg="#0b1220")
        self.analytics_container.pack(fill="both", expand=True, padx=12, pady=12)

    def load_analytics(self):
        for widget in self.analytics_container.winfo_children():
            widget.destroy()

        severity_data = get_severity_counts()
        timeline_data = get_logs_over_time()
        source_data = get_top_sources()

        # Top row
        top_row = tk.Frame(self.analytics_container, bg="#0b1220")
        top_row.pack(fill="both", expand=True)

        # Severity Pie Chart
        fig1 = Figure(figsize=(4, 3), dpi=100)
        ax1 = fig1.add_subplot(111)

        if severity_data:
            labels = [row[0] for row in severity_data]
            sizes = [row[1] for row in severity_data]
            ax1.pie(sizes, labels=labels, autopct="%1.1f%%")
            ax1.set_title("Severity Distribution")
        else:
            ax1.text(0.5, 0.5, "No data", ha="center", va="center")
            ax1.set_title("Severity Distribution")

        canvas1 = FigureCanvasTkAgg(fig1, master=top_row)
        canvas1.draw()
        canvas1.get_tk_widget().pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Logs Over Time Line Chart
        fig2 = Figure(figsize=(4, 3), dpi=100)
        ax2 = fig2.add_subplot(111)

        if timeline_data:
            times = [row[0] for row in timeline_data]
            counts = [row[1] for row in timeline_data]
            ax2.plot(times, counts, marker="o")
            ax2.set_title("Logs Over Time")
            ax2.set_xlabel("Time")
            ax2.set_ylabel("Log Count")
            ax2.tick_params(axis='x', rotation=45)
        else:
            ax2.text(0.5, 0.5, "No data", ha="center", va="center")
            ax2.set_title("Logs Over Time")

        canvas2 = FigureCanvasTkAgg(fig2, master=top_row)
        canvas2.draw()
        canvas2.get_tk_widget().pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Bottom row
        bottom_row = tk.Frame(self.analytics_container, bg="#0b1220")
        bottom_row.pack(fill="both", expand=True)

        # Top Sources Bar Chart
        fig3 = Figure(figsize=(8, 3), dpi=100)
        ax3 = fig3.add_subplot(111)

        if source_data:
            sources = [row[0] for row in source_data]
            counts = [row[1] for row in source_data]
            ax3.bar(sources, counts)
            ax3.set_title("Top Sources")
            ax3.set_xlabel("Source")
            ax3.set_ylabel("Log Count")
            ax3.tick_params(axis='x', rotation=20)
        else:
            ax3.text(0.5, 0.5, "No data", ha="center", va="center")
            ax3.set_title("Top Sources")

        canvas3 = FigureCanvasTkAgg(fig3, master=bottom_row)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

    # ---------------- HIGH POPUP (stable) ----------------
    def _get_latest_high_id(self):
        try:
            self.cursor.execute("SELECT COALESCE(MAX(id), 0) FROM logs WHERE severity='HIGH'")
            return int(self.cursor.fetchone()[0])
        except Exception:
            return 0

    def _check_new_high_popup(self):
        if not hasattr(self, "popup_var") or not self.popup_var.get():
            return

        self.cursor.execute("""
            SELECT id, timestamp, source, log_type, message
            FROM logs
            WHERE severity = 'HIGH'
            ORDER BY id DESC
            LIMIT 1
        """)
        row = self.cursor.fetchone()
        if not row:
            return

        _id, ts, src, lt, msg = row
        if _id <= self.last_seen_high_id:
            return

        self.last_seen_high_id = _id
        messagebox.showwarning(
            "HIGH Alert Detected!",
            f"ID: {_id}\nTime: {ts}\nSource: {src}\nType: {lt}\n\n{msg}"
        )

    # ---------------- REPORT ----------------
    def generate_report(self):
        try:
            out = generate_pdf_report("siem_report.pdf", hours=24)
            messagebox.showinfo("Report Generated", f"PDF report created:\n{out}")
        except Exception as e:
            messagebox.showerror("Report Error", str(e))

    def report_missing(self):
        messagebox.showinfo(
            "Report not available",
            "report.py not found or generate_pdf_report could not be imported.\n\n"
            "Place report.py in the same folder and ensure it has generate_pdf_report()."
        )

    # ---------------- AUTO REFRESH ----------------
    def auto_refresh(self):
        self.refresh_current_view()
        self._check_new_high_popup()
        self.after(AUTO_REFRESH_MS, self.auto_refresh)

    # ---------------- HELPERS ----------------
    def _tree_clear(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def on_exit(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    # Start with login window; it will launch the dashboard after successful login
    LoginWindow().mainloop()
