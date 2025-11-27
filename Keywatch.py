import os
import sys
import threading
from datetime import datetime, timedelta
from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk, ImageDraw, ImageFont
from pynput import keyboard
from cryptography.fernet import Fernet
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
APP_TITLE = "Xencore KeyWatch — Modern"
LOGS_DIR = "xencore_logs"
KEY_FILE = "xencore_key.key"
APP_PASSWORD_FILE = "xencore_pass.token"
REALTIME_MAX_CHARS = 60000
PLOT_BUCKET_SEC = 30
# color palette (modern)
BG = "#081421"
PANEL = "#0e2633"
ACCENT = "#22c1c3"
ACCENT2 = "#6be3d9"
TEXT = "#e6f9fb"
MUTED = "#9fb7bd"
os.makedirs(LOGS_DIR, exist_ok=True)
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        k = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(k)
    else:
        with open(KEY_FILE, "rb") as f:
            k = f.read()
    return k
FERNET_KEY = load_or_create_key()
CIPHER = Fernet(FERNET_KEY)
def set_app_password(pw: str):
    token = CIPHER.encrypt(pw.encode())
    with open(APP_PASSWORD_FILE, "wb") as f:
        f.write(token)
def check_app_password(pw: str) -> bool:
    if not os.path.exists(APP_PASSWORD_FILE):
        return False
    try:
        with open(APP_PASSWORD_FILE, "rb") as f:
            tok = f.read()
        stored = CIPHER.decrypt(tok).decode()
        return stored == pw
    except Exception:
        return False
class KeyWatch:
    def __init__(self, realtime_callback=None):
        self.listener = None
        self.running = False
        self.buffer = []  # list of (iso_ts, char)
        self.lock = threading.Lock()
        self.realtime_callback = realtime_callback
    def _on_press(self, key):
        ts = datetime.utcnow().isoformat() + "Z"
        try:
            ch = key.char
        except AttributeError:
            ch = f"[{getattr(key, 'name', str(key))}]"
        entry = (ts, ch)
        with self.lock:
            self.buffer.append(entry)
            if len(self.buffer) > 30000:
                self.buffer = self.buffer[-30000:]
        if self.realtime_callback:
            try:
                self.realtime_callback(entry)
            except Exception:
                pass
    def start(self):
        if self.running:
            return
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.start()
        self.running = True
    def stop(self):
        if not self.running:
            return
        if self.listener:
            self.listener.stop()
        self.running = False
        self._save_buffer()
        with self.lock:
            self.buffer = []
    def _save_buffer(self):
        with self.lock:
            if not self.buffer:
                return
            ts = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
            fname = os.path.join(LOGS_DIR, f"log_{ts}.xclog")
            txt = "\n".join([f"{t}\t{c}" for (t, c) in self.buffer]).encode()
            token = CIPHER.encrypt(txt)
            with open(fname, "wb") as f:
                f.write(token)
    def list_logs(self):
        items = []
        for f in sorted(os.listdir(LOGS_DIR), reverse=True):
            if f.endswith(".xclog"):
                mtime = datetime.utcfromtimestamp(os.path.getmtime(os.path.join(LOGS_DIR, f)))
                items.append((f, datetime.utcfromtimestamp(os.path.getmtime(os.path.join(LOGS_DIR, f)))))
        return items
    def read_log(self, filename):
        path = os.path.join(LOGS_DIR, filename)
        with open(path, "rb") as f:
            token = f.read()
        plain = CIPHER.decrypt(token).decode(errors="replace")
        rows = []
        for line in plain.splitlines():
            if "\t" in line:
                t, c = line.split("\t", 1)
                rows.append((t, c))
        return rows
def create_frequency_png(entries, out_path, bucket_sec=PLOT_BUCKET_SEC):
    if not entries:
        plt.figure(figsize=(6,2))
        plt.text(0.5,0.5,"No typing data", ha="center", va="center")
        plt.axis("off")
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return
    times = [datetime.fromisoformat(t.replace("Z","")) for (t,c) in entries]
    start = min(times)
    end = max(times)
    total_seconds = int((end - start).total_seconds()) + 1
    num_buckets = max(1, (total_seconds // bucket_sec) + 1)
    counts = [0]*num_buckets
    for t in times:
        idx = int((t - start).total_seconds()) // bucket_sec
        if idx < len(counts):
            counts[idx] += 1
    labels = [(start + timedelta(seconds=i*bucket_sec)).strftime("%H:%M") for i in range(len(counts))]
    plt.figure(figsize=(8,2.4))
    plt.plot(labels, counts, marker='o', linewidth=1.5)
    plt.fill_between(labels, counts, alpha=0.15)
    plt.xticks(rotation=45)
    plt.grid(alpha=0.12)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
def export_log_to_pdf(filename, entries, out_pdf_path):
    text_lines = [f"{t}    {c}" for (t,c) in entries]
    plain_text = "\n".join(text_lines)
    tmp_png = os.path.join(LOGS_DIR, "tmp_typing_plot.png")
    create_frequency_png(entries, tmp_png)
    c = canvas.Canvas(out_pdf_path, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20*mm, height - 20*mm, "Xencore KeyWatch - Log Export")
    c.setFont("Helvetica", 9)
    c.drawString(20*mm, height - 26*mm, f"Source: {filename}")
    c.drawString(20*mm, height - 32*mm, f"Exported: {datetime.utcnow().isoformat()}Z")
    try:
        c.drawImage(tmp_png, 20*mm, height - 100*mm, width=170*mm, height=50*mm, preserveAspectRatio=True)
    except Exception:
        pass
    text_obj = c.beginText(20*mm, height - 110*mm)
    text_obj.setFont("Courier", 8)
    for line in plain_text.splitlines():
        while len(line) > 110:
            text_obj.textLine(line[:110])
            line = line[110:]
            if text_obj.getY() < 20*mm:
                c.drawText(text_obj); c.showPage()
                text_obj = c.beginText(20*mm, height - 20*mm); text_obj.setFont("Courier", 8)
        text_obj.textLine(line)
        if text_obj.getY() < 20*mm:
            c.drawText(text_obj); c.showPage()
            text_obj = c.beginText(20*mm, height - 20*mm); text_obj.setFont("Courier", 8)
    c.drawText(text_obj)
    c.save()
    try:
        os.remove(tmp_png)
    except Exception:
        pass
def guess_desktop_logo_paths():
    home = os.path.expanduser("~")
    candidates = []
    candidates.append(os.path.join(home, "Desktop", "Keywatch", "aa.png"))
    candidates.append(os.path.join(home, "Desktop", "Keywatch", "aa.jpg"))
    candidates.append(os.path.join(home, "Desktop", "Keywatch", "logo.png"))
    candidates.append(os.path.join(home, "Desktop", "aa.png"))
    candidates.append(os.path.join(home, "Downloads", "aa.png"))
    if os.name == "nt":
        user = os.environ.get("USERPROFILE", home)
        candidates.append(os.path.join(user, "Desktop", "Keywatch", "aa.png"))
    return candidates
def load_logo_image(size=78):
    for p in guess_desktop_logo_paths():
        if os.path.exists(p):
            try:
                img = Image.open(p).convert("RGBA")
                img = img.resize((size, size), Image.LANCZOS)
                return ImageTk.PhotoImage(img)
            except Exception:
                continue
    img = Image.new("RGBA", (size, size), (0,0,0,0))
    draw = ImageDraw.Draw(img)
    # gradient circle
    for r in range(size//2, 0, -1):
        t = int(20 + (size//2 - r) * 3)
        draw.ellipse((size//2 - r, size//2 - r, size//2 + r, size//2 + r), fill=(12 + t, 50 + t, 80 + t, 255))
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", size//2)
    except Exception:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0,0), "aa", font=font)
    w = bbox[2]-bbox[0]; h = bbox[3]-bbox[1]
    draw.text(((size-w)/2, (size-h)/2 - 2), "aa", font=font, fill=(255,255,255,255))
    return ImageTk.PhotoImage(img)
class ModernApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("1050x720")
        root.configure(bg=BG)
        self.keywatch = KeyWatch(realtime_callback=self.on_realtime_event)
        self.event_queue = deque(maxlen=20000)
        header = tk.Frame(root, bg=PANEL, height=84)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        self.logo_img = load_logo_image(72)
        lbl_logo = tk.Label(header, image=self.logo_img, bg=PANEL)
        lbl_logo.pack(side="left", padx=16, pady=6)
        title_frame = tk.Frame(header, bg=PANEL)
        title_frame.pack(side="left", padx=(6,12))
        tk.Label(title_frame, text="Xencore KeyWatch", bg=PANEL, fg=TEXT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(title_frame, text="Professional — Consent first", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        ctrl_frame = tk.Frame(header, bg=PANEL)
        ctrl_frame.pack(side="right", padx=12)
        self.start_btn = ttk.Button(ctrl_frame, text="Start", command=self.start, width=10)
        self.stop_btn = ttk.Button(ctrl_frame, text="Stop", command=self.stop, width=10)
        self.export_btn = ttk.Button(ctrl_frame, text="Export PDF", command=self.export_selected, width=12)
        self.refresh_btn = ttk.Button(ctrl_frame, text="Refresh Logs", command=self.refresh_logs, width=12)
        self.pass_btn = ttk.Button(ctrl_frame, text="Password", command=self.set_password, width=10)
        self.start_btn.pack(side="left", padx=6, pady=14)
        self.stop_btn.pack(side="left", padx=6, pady=14)
        self.export_btn.pack(side="left", padx=6, pady=14)
        self.refresh_btn.pack(side="left", padx=6, pady=14)
        self.pass_btn.pack(side="left", padx=6, pady=14)
        main = tk.Frame(root, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=12)
        left = tk.Frame(main, bg=BG, width=320)
        left.pack(side="left", fill="y", padx=(0,12))
        left.pack_propagate(False)
        tk.Label(left, text="Saved Logs", bg=BG, fg=TEXT, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,8))
        self.logs_list = tk.Listbox(left, bg="#04222b", fg=TEXT, width=46, height=28, selectbackground="#06383f", bd=0)
        self.logs_list.pack(fill="y", expand=True)
        tk.Button(left, text="View Selected", bg=ACCENT, fg="#062225", command=self.view_selected, relief="flat").pack(fill="x", pady=8)
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        card1 = tk.Frame(right, bg=PANEL, bd=0, relief="flat")
        card1.pack(fill="both", expand=False)
        tk.Label(card1, text="Real-time Stream", bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(8,0))
        self.stream = ScrolledText(card1, height=12, bg="#041821", fg=ACCENT2, font=("Consolas",10), bd=0)
        self.stream.pack(fill="both", padx=10, pady=(6,12))
        card2 = tk.Frame(right, bg=PANEL)
        card2.pack(fill="x", pady=(10,0))
        tk.Label(card2, text="Typing Frequency (live preview)", bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(8,0))
        self.plot_canvas = tk.Canvas(card2, height=160, bg=PANEL, bd=0, highlightthickness=0)
        self.plot_canvas.pack(fill="x", padx=10, pady=8)
        card3 = tk.Frame(right, bg=PANEL)
        card3.pack(fill="both", expand=True, pady=(10,0))
        tk.Label(card3, text="Preview / Viewer", bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(8,0))
        self.preview = ScrolledText(card3, bg="#031020", fg=TEXT, font=("Courier",10), bd=0)
        self.preview.pack(fill="both", expand=True, padx=10, pady=8)
        self.status = tk.Label(root, text="Ready — Use only with explicit authorization.", bg="#021216", fg=MUTED, anchor="w")
        self.status.pack(fill="x", side="bottom")
        self.refresh_logs()
        self._start_plot_updater()
    def start(self):
        if not os.path.exists(APP_PASSWORD_FILE):
            if messagebox.askyesno("Password", "No app password set. Set one now?"):
                self.set_password()
        ok = messagebox.askyesno("Consent", "Do you have explicit authorization to monitor this device? Only continue if you do.")
        if not ok:
            return
        try:
            self.keywatch.start()
            self.start_btn.state(["disabled"])
            self.status.configure(text="Running (visible). Logs will be saved encrypted when you stop.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start listener: {e}")
    def stop(self):
        try:
            self.keywatch.stop()
            self.start_btn.state(["!disabled"])
            self.status.configure(text="Stopped. Logs saved encrypted.")
            self.refresh_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop listener: {e}")
    def on_realtime_event(self, entry):
        self.event_queue.append(entry)
        self.root.after(0, lambda: self._append_stream(entry))
    def _append_stream(self, entry):
        ts, ch = entry
        self.stream.configure(state="normal")
        self.stream.insert("end", f"{ts}    {ch}\n")
        self.stream.see("end")
        content = self.stream.get("1.0", "end")
        if len(content) > REALTIME_MAX_CHARS:
            self.stream.delete("1.0", "1.0 + 24000 chars")
        self.stream.configure(state="disabled")
    def refresh_logs(self):
        self.logs_list.delete(0, "end")
        for fname, mtime in self.keywatch.list_logs():
            self.logs_list.insert("end", f"{fname}    ({mtime.strftime('%Y-%m-%d %H:%M:%S')} UTC)")
    def view_selected(self):
        sel = self.logs_list.curselection()
        if not sel:
            messagebox.showwarning("Select", "Select a saved log to view")
            return
        label = self.logs_list.get(sel[0])
        fname = label.split()[0]
        if not self._require_password():
            return
        try:
            rows = self.keywatch.read_log(fname)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read log: {e}")
            return
        self.preview.configure(state="normal"); self.preview.delete("1.0", "end")
        for t,c in rows:
            self.preview.insert("end", f"{t}    {c}\n")
        self.preview.configure(state="disabled")
        self._render_plot(rows)
    def export_selected(self):
        sel = self.logs_list.curselection()
        if not sel:
            messagebox.showwarning("Select", "Select a saved log to export")
            return
        label = self.logs_list.get(sel[0])
        fname = label.split()[0]
        if not self._require_password():
            return
        try:
            rows = self.keywatch.read_log(fname)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read log: {e}")
            return
        out = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files","*.pdf")])
        if not out:
            return
        try:
            export_log_to_pdf(fname, rows, out)
            messagebox.showinfo("Exported", f"PDF saved to {out}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export PDF: {e}")
    def set_password(self):
        dlg = tk.Toplevel(self.root); dlg.title("Set App Password"); dlg.geometry("360x160")
        ttk.Label(dlg, text="New password:").pack(pady=(12,4))
        e1 = ttk.Entry(dlg, show="*"); e1.pack(fill="x", padx=12)
        ttk.Label(dlg, text="Confirm password:").pack(pady=(8,4))
        e2 = ttk.Entry(dlg, show="*"); e2.pack(fill="x", padx=12)
        def save_pw():
            p1 = e1.get().strip(); p2 = e2.get().strip()
            if not p1:
                messagebox.showwarning("Password","Cannot be empty"); return
            if p1 != p2:
                messagebox.showwarning("Password","Passwords do not match"); return
            set_app_password(p1); messagebox.showinfo("Saved","Password saved"); dlg.destroy()
        ttk.Button(dlg, text="Save", command=save_pw).pack(pady=12)
    def _require_password(self):
        if not os.path.exists(APP_PASSWORD_FILE):
            return messagebox.askyesno("No password", "No password set. Continue without password?")
        dlg = tk.Toplevel(self.root); dlg.title("Enter Password"); dlg.geometry("320x120")
        ttk.Label(dlg, text="App password:").pack(pady=(12,4))
        ent = ttk.Entry(dlg, show="*"); ent.pack(fill="x", padx=12)
        result = {"ok": False}
        def check_close():
            if check_app_password(ent.get().strip()):
                result["ok"] = True; dlg.destroy()
            else:
                messagebox.showerror("Access Denied","Incorrect password")
        ttk.Button(dlg, text="OK", command=check_close).pack(pady=10)
        self.root.wait_window(dlg)
        return result["ok"]
    def _render_plot(self, rows):
        tmp = os.path.join(LOGS_DIR, "tmp_live_plot.png")
        create_frequency_png(rows, tmp)
        try:
            img = Image.open(tmp).resize((self.plot_canvas.winfo_width() or 900, 160), Image.LANCZOS)
            self.plot_tk = ImageTk.PhotoImage(img)
            self.plot_canvas.delete("all")
            self.plot_canvas.create_image(0,0, anchor="nw", image=self.plot_tk)
        except Exception:
            pass
        try:
            os.remove(tmp)
        except Exception:
            pass
    def _start_plot_updater(self):
        def updater():
            if self.event_queue:
                sample = list(self.event_queue)[-1400:]
                rows = [(t,c) for (t,c) in sample]
                self._render_plot(rows)
            self.root.after(2000, updater)
        updater()
if __name__ == "__main__":
    root = tk.Tk()
    # ttk style tweaks
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    # create and run app
    app = ModernApp(root)
    root.mainloop()