#!/usr/bin/env python3
"""
PySecScope - Final Release
Un tool di enumeration per sistemi Linux, con interfaccia grafica Tkinter,
ispirato a LinEnum. Include esclusioni per directory /proc, /sys, /dev,
logging avanzato, moduli di scansione (inclusi nuovi moduli per log e pacchetti installati),
supporto report in Text, JSON e CSV, interruzione della scansione e controllo dei privilegi.
"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import json
from datetime import datetime
import configparser
import logging
import time
import csv
import io

# ---------------------------
# CONFIGURAZIONE DA FILE
# ---------------------------
config = configparser.ConfigParser()
if os.path.exists("pysecscope.ini"):
    config.read("pysecscope.ini")
    DEFAULT_EXPORT_DIR = config.get("Settings", "export_directory", fallback="")
    DEFAULT_THOROUGH = config.getboolean("Settings", "thorough", fallback=False)
    DEFAULT_REPORT_FORMAT = config.get("Settings", "report_format", fallback="Text")
else:
    DEFAULT_EXPORT_DIR = ""
    DEFAULT_THOROUGH = False
    DEFAULT_REPORT_FORMAT = "Text"

# ---------------------------
# SETTAGGIO DEL LOGGING
# ---------------------------
logging.basicConfig(
    filename="pysecscope.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("PySecScope final release avviato")

# Costante per le directory da escludere nelle ricerche
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
def get_exclude_clause():
    # Costruisce la clausola di esclusione da usare nei comandi find
    clause = r"\( " + " -o ".join([f"-path {d}" for d in EXCLUDE_DIRS]) + r" \) -prune -o"
    return clause

# ---------------------------
# UTILITÀ: Esecuzione di comandi
# ---------------------------
def run_command(cmd):
    logger.debug(f"Esecuzione comando: {cmd}")
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
        )
        logger.debug(f"Output: {output[:100]}...")
        return output
    except subprocess.CalledProcessError as e:
        logger.error(f"Errore comando {cmd}: {e.output}")
        return f"Errore: {e.output}"

# ---------------------------
# FUNZIONI DI SCANSIONE DI BASE
# ---------------------------
def get_system_info():
    logger.info("Raccolta informazioni di sistema")
    info = "==== SYSTEM INFO ====\n" + run_command("uname -a") + "\n"
    try:
        for f in os.listdir("/etc"):
            if "release" in f.lower() or "version" in f.lower():
                try:
                    with open(os.path.join("/etc", f), "r") as file:
                        info += f"--- {f} ---\n" + file.read() + "\n"
                except Exception as ex:
                    logger.error(f"Errore lettura {f}: {ex}")
                    continue
    except Exception as e:
        info += "Impossibile leggere file di release.\n"
        logger.error(f"Errore directory /etc: {e}")
    return info

def get_user_info():
    logger.info("Raccolta informazioni utente")
    info = "==== USER INFO ====\n" + run_command("id") + "\n"
    try:
        with open("/etc/passwd", "r") as f:
            info += "\n--- /etc/passwd ---\n" + f.read() + "\n"
    except Exception as e:
        info += "Impossibile leggere /etc/passwd\n"
        logger.error(f"Errore lettura /etc/passwd: {e}")
    return info

def get_network_info():
    logger.info("Raccolta informazioni di rete")
    info = "==== NETWORK INFO ====\n"
    out = run_command("ip a")
    if not out.strip():
        out = run_command("ifconfig -a")
    info += out + "\n"
    info += "\n--- ARP ---\n" + run_command("arp -a") + "\n"
    info += "\n--- Default Route ---\n" + run_command("ip route") + "\n"
    try:
        with open("/etc/resolv.conf", "r") as f:
            info += "\n--- /etc/resolv.conf ---\n" + f.read() + "\n"
    except Exception as e:
        info += "Impossibile leggere /etc/resolv.conf\n"
        logger.error(f"Errore lettura /etc/resolv.conf: {e}")
    return info

def get_services_info():
    logger.info("Raccolta informazioni servizi")
    info = "==== SERVICES INFO ====\n" + "\n--- Processi Correnti (ps aux) ---\n" + run_command("ps aux") + "\n"
    out = run_command("netstat -tulpn")
    if not out.strip():
        out = run_command("ss -tulpn")
    info += "\n--- Porte in Ascolto ---\n" + out + "\n"
    return info

def search_keyword_in_files(keyword, file_pattern, max_depth=4):
    logger.info(f"Ricerca keyword '{keyword}' in file {file_pattern} (max_depth={max_depth})")
    exclude_clause = get_exclude_clause()
    cmd = f"find / {exclude_clause} -maxdepth {max_depth} -type f -name '{file_pattern}' -exec grep -Hn '{keyword}' {{}} \\; 2>/dev/null"
    result = run_command(cmd)
    if not result.strip():
        result = f"Nessuna corrispondenza per '{keyword}' in file {file_pattern}\n"
    return result

def get_file_search_info(keyword):
    info = "==== FILE SEARCH (Keyword) ====\n"
    for ext, depth in [("*.conf", 4), ("*.php", 10), ("*.log", 4), ("*.ini", 4)]:
        info += f"\n--- Ricerca in file {ext} ---\n" + search_keyword_in_files(keyword, ext, depth) + "\n"
    return info

def container_checks():
    logger.info("Esecuzione controlli container")
    info = "==== CONTAINER CHECKS ====\n"
    docker_check = run_command("grep -i docker /proc/self/cgroup")
    if docker_check.strip():
        info += "Docker container rilevato:\n" + docker_check + "\n"
    else:
        info += "Non in un Docker container.\n"
    if os.path.exists("/.dockerenv"):
        info += "Trovato '/.dockerenv': probabilmente in Docker.\n"
    try:
        with open("/proc/1/environ", "rb") as f:
            env = f.read().decode(errors="ignore")
        if "container=lxc" in env:
            info += "LXC container rilevato.\n"
        else:
            info += "Non in un LXC container.\n"
    except Exception as e:
        info += "Impossibile controllare /proc/1/environ per LXC.\n"
        logger.error(f"Errore lettura /proc/1/environ: {e}")
    return info

def get_suid_info():
    logger.info("Ricerca file SUID")
    exclude_clause = get_exclude_clause()
    cmd = f"find / {exclude_clause} -type f -perm -4000 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SUID trovato.\n"
    else:
        return "==== SUID FILES ====\n" + output + "\n"

def get_sgid_info():
    logger.info("Ricerca file SGID")
    exclude_clause = get_exclude_clause()
    cmd = f"find / {exclude_clause} -type f -perm -2000 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SGID trovato.\n"
    else:
        return "==== SGID FILES ====\n" + output + "\n"

def get_capabilities_info():
    logger.info("Ricerca capabilities POSIX")
    output = run_command("getcap -r / 2>/dev/null")
    if not output.strip():
        return "Nessun file con capabilities POSIX trovato.\n"
    else:
        return "==== FILES WITH CAPABILITIES ====\n" + output + "\n"

def get_plan_files():
    logger.info("Ricerca file .plan")
    exclude_clause = get_exclude_clause()
    cmd = f"find /home {exclude_clause} -type f -iname '*.plan' -exec ls -la {{}} \\; 2>/dev/null"
    output = run_command(cmd)
    if output.strip():
        return "==== Plan Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .plan trovato in /home.\n"

def get_rhosts_files():
    logger.info("Ricerca file .rhosts")
    exclude_clause = get_exclude_clause()
    cmd = f"find /home {exclude_clause} -type f -iname '*.rhosts' -exec ls -la {{}} \\; 2>/dev/null"
    output = run_command(cmd)
    if output.strip():
        return "==== .rhosts Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .rhosts trovato in /home.\n"

def get_bash_history():
    logger.info("Ricerca file .bash_history")
    exclude_clause = get_exclude_clause()
    cmd = f"find /home {exclude_clause} -type f -name '.bash_history' -exec ls -la {{}} \\; -exec cat {{}} \\; 2>/dev/null"
    output = run_command(cmd)
    if output.strip():
        return "==== .bash_history Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .bash_history accessibile in /home.\n"

def get_bak_files():
    logger.info("Ricerca file .bak")
    exclude_clause = get_exclude_clause()
    cmd = f"find / {exclude_clause} -type f -iname '*.bak' 2>/dev/null"
    output = run_command(cmd)
    if output.strip():
        return "==== .bak Files ====\n" + output + "\n"
    else:
        return "Nessun file .bak trovato.\n"

def get_mail_info():
    logger.info("Ricerca informazioni mail")
    info = "==== MAIL INFO ====\n" + run_command("ls -la /var/mail") + "\n"
    root_mail = run_command("head /var/mail/root")
    if root_mail.strip():
        info += "\n--- /var/mail/root (snippet) ---\n" + root_mail + "\n"
    return info

def get_cron_jobs_info():
    logger.info("Ricerca informazioni su cron jobs")
    try:
        crontab = run_command("cat /etc/crontab")
        cron_spool = run_command("ls -la /var/spool/cron 2>/dev/null")
        cron_info = "---- /etc/crontab ----\n" + crontab + "\n---- /var/spool/cron ----\n" + cron_spool
        return "==== CRON JOBS INFO ====\n" + cron_info + "\n"
    except Exception as e:
        logger.error(f"Errore cron jobs: {e}")
        return f"Errore nella lettura dei cron jobs: {e}\n"

def get_sudoers_info():
    logger.info("Raccolta informazioni del file sudoers")
    try:
        sudoers = run_command("cat /etc/sudoers 2>/dev/null")
        if not sudoers.strip():
            return "Non è possibile leggere /etc/sudoers o il file è vuoto.\n"
        return "==== SUDOERS INFO ====\n" + sudoers + "\n"
    except Exception as e:
        logger.error(f"Errore lettura /etc/sudoers: {e}")
        return f"Errore nella lettura di /etc/sudoers: {e}\n"

def get_firewall_info():
    logger.info("Ricerca informazioni del firewall (iptables)")
    output = run_command("iptables -L 2>/dev/null")
    if not output.strip():
        return "Impossibile leggere le regole del firewall (iptables).\n"
    else:
        return "==== FIREWALL INFO (iptables) ====\n" + output + "\n"

def get_log_files_info():
    logger.info("Raccolta informazioni da /var/log")
    try:
        log_files = os.listdir("/var/log")
        files = "\n".join(log_files)
        return "==== LOG FILES INFO in /var/log ====\n" + files + "\n"
    except Exception as e:
        logger.error(f"Errore lettura /var/log: {e}")
        return f"Errore nella lettura di /var/log: {e}\n"

def get_installed_packages_info():
    logger.info("Raccolta informazioni pacchetti installati")
    dpkg_output = run_command("dpkg -l 2>/dev/null")
    if dpkg_output.strip():
        return "==== INSTALLED PACKAGES (dpkg) ====\n" + dpkg_output + "\n"
    rpm_output = run_command("rpm -qa 2>/dev/null")
    if rpm_output.strip():
        return "==== INSTALLED PACKAGES (rpm) ====\n" + rpm_output + "\n"
    return "Nessuna informazione sui pacchetti trovata.\n"

# ---------------------------
# GESTIONE DEI MODULI (PLUGIN)
# ---------------------------
def get_default_modules(thorough=False):
    modules = [
        ("System Info", get_system_info),
        ("User Info", get_user_info),
        ("Network Info", get_network_info),
        ("Services Info", get_services_info),
        ("Container Checks", container_checks),
    ]
    if thorough:
        modules.extend([
            ("SUID Info", get_suid_info),
            ("SGID Info", get_sgid_info),
            ("Capabilities Info", get_capabilities_info),
            ("Plan Files", get_plan_files),
            ("Rhosts Files", get_rhosts_files),
            ("Bash History", get_bash_history),
            ("Backup Files", get_bak_files),
            ("Mail Info", get_mail_info),
            ("Cron Jobs Info", get_cron_jobs_info),
            ("Sudoers Info", get_sudoers_info),
            ("Firewall Info", get_firewall_info),
            ("Log Files Info", get_log_files_info),
            ("Installed Packages Info", get_installed_packages_info)
        ])
    return modules

# ---------------------------
# FUNZIONE DI SCANSIONE AGGREGATA CON MODULI E REPORT MULTIFORMATO
# ---------------------------
def run_scan(options, selected_modules, report_format="Text"):
    start_time = time.time()
    if report_format == "JSON":
        results_dict = {}
    elif report_format == "CSV":
        csv_rows = []
    else:
        results_str = ""
        
    num_modules = len(selected_modules)
    progress_counter = 0
    
    for module_name, module_func in selected_modules:
        if options["cancel_event"].is_set():
            if report_format == "JSON":
                results_dict["Interrupted"] = "La scansione è stata interrotta dall'utente."
            elif report_format == "CSV":
                csv_rows.append(["Interrupted", "La scansione è stata interrotta dall'utente."])
            else:
                results_str += "\nLa scansione è stata interrotta dall'utente.\n"
            logger.info("Scansione interrotta dall'utente")
            break
        
        result = module_func()
        if report_format == "JSON":
            results_dict[module_name] = result
        elif report_format == "CSV":
            # Per il CSV, ogni riga è del tipo: <Module>, <Result>
            csv_rows.append([module_name, result.replace('\n', ' ')])
        else:
            results_str += f"===== {module_name} =====\n{result}\n"
        progress_counter += 1
        options["progress_callback"](progress_counter, num_modules)
    
    elapsed = time.time() - start_time
    finish_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = f"\n----- Scansione completata alle {finish_stamp} in {elapsed:.2f} secondi -----\n"
    
    if report_format == "JSON":
        results_dict["Summary"] = summary
        final_result = json.dumps(results_dict, indent=4)
    elif report_format == "CSV":
        # Costruiamo il CSV in memoria
        output_csv = io.StringIO()
        writer = csv.writer(output_csv)
        writer.writerow(["Module", "Result"])
        for row in csv_rows:
            writer.writerow(row)
        writer.writerow(["Summary", summary])
        final_result = output_csv.getvalue()
    else:
        final_result = results_str + summary
    
    if options.get("export"):
        try:
            now = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            export_dir = options.get("export")
            ext = "json" if report_format == "JSON" else ("csv" if report_format == "CSV" else "txt")
            filename = os.path.join(export_dir, f"PySecScope_report_{now}.{ext}")
            with open(filename, "w") as f:
                f.write(final_result)
            final_result += "\nReport esportato in: " + filename + "\n"
            logger.info(f"Report esportato in: {filename}")
        except Exception as e:
            final_result += "\nErrore durante l'esportazione del report: " + str(e) + "\n"
            logger.error(f"Errore export report: {e}")
    
    return final_result

# ---------------------------
# DIALOGO "ABOUT"
# ---------------------------
def show_about():
    about_text = (
        "PySecScope v5 (Final Release)\n"
        "Tool di enumeration per sistemi Linux con GUI Tkinter.\n"
        "Ispirato a LinEnum e sviluppato in Python.\n"
        "Autore: il nostro team\n"
        "Anno: " + datetime.now().strftime("%Y") + "\n\n"
        "Questo tool è destinato esclusivamente ad usi autorizzati e in ambienti di test."
    )
    messagebox.showinfo("About PySecScope", about_text)

# ---------------------------
# INTERFACCIA GRAFICA CON TKINTER
# ---------------------------
class PySecScopeGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PySecScope v5 - Python Security Scope")
        self.geometry("1000x800")
        self.cancel_event = threading.Event()  # Per gestire la cancellazione
        self.create_menu()
        self.create_widgets()
        self.check_privileges()

    def create_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Esci", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def create_widgets(self):
        options_frame = ttk.LabelFrame(self, text="Opzioni")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(options_frame, text="Keyword:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=2)
        self.keyword_entry = ttk.Entry(options_frame, width=30)
        self.keyword_entry.grid(column=1, row=0, padx=5, pady=2)
        ttk.Label(options_frame, text="Export Directory:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=2)
        self.export_entry = ttk.Entry(options_frame, width=30)
        self.export_entry.grid(column=1, row=1, padx=5, pady=2)
        export_btn = ttk.Button(options_frame, text="Sfoglia", command=self.browse_export_dir)
        export_btn.grid(column=2, row=1, padx=5, pady=2)
        self.thorough_var = tk.BooleanVar(value=DEFAULT_THOROUGH)
        ttk.Checkbutton(options_frame, text="Modalità Thorough", variable=self.thorough_var).grid(column=0, row=2, padx=5, pady=2)
        ttk.Label(options_frame, text="Formato Report:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=2)
        self.report_format_cb = ttk.Combobox(options_frame, values=["Text", "JSON", "CSV"], state="readonly", width=10)
        default_format = DEFAULT_REPORT_FORMAT if DEFAULT_REPORT_FORMAT in ["Text", "JSON", "CSV"] else "Text"
        self.report_format_cb.set(default_format)
        self.report_format_cb.grid(column=1, row=3, padx=5, pady=2)
        modules_frame = ttk.LabelFrame(self, text="Moduli di Scansione")
        modules_frame.pack(fill=tk.X, padx=10, pady=5)
        self.module_vars = {}
        default_modules = get_default_modules(self.thorough_var.get())
        row_index = 0
        for module_name, _ in default_modules:
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(modules_frame, text=module_name, variable=var)
            chk.grid(column=0, row=row_index, sticky=tk.W, padx=5, pady=2)
            self.module_vars[module_name] = var
            row_index += 1
        action_frame = ttk.Frame(self)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        self.start_btn = ttk.Button(action_frame, text="Avvia Scansione", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = ttk.Button(action_frame, text="Stop Scansione", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.progress_bar = ttk.Progressbar(self, orient='horizontal', mode='determinate', length=300)
        self.progress_bar.pack(padx=10, pady=5)
        self.status_label = ttk.Label(self, text="Pronto")
        self.status_label.pack(padx=10, pady=5)
        self.log_output = ScrolledText(self, wrap=tk.WORD, height=30)
        self.log_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    def browse_export_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.export_entry.delete(0, tk.END)
            self.export_entry.insert(0, directory)

    def update_progress(self, current, total):
        progress_percent = int((current / total) * 100)
        self.progress_bar['value'] = progress_percent
        self.status_label.config(text=f"Scansione in corso... ({progress_percent}%)")
        self.update_idletasks()

    def check_privileges(self):
        # Se non si è root, avvisa l'utente
        if os.getuid() != 0:
            messagebox.showwarning("Attenzione", "Non stai eseguendo il tool con privilegi di root. Alcuni moduli potrebbero non funzionare correttamente.")
            logger.warning("Esecuzione senza root; alcuni moduli potrebbero essere limitati.")

    def start_scan(self):
        self.cancel_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        options = {
            "keyword": self.keyword_entry.get().strip(),
            "export": self.export_entry.get().strip() or DEFAULT_EXPORT_DIR,
            "thorough": self.thorough_var.get(),
            "progress_callback": self.update_progress,
            "cancel_event": self.cancel_event
        }
        report_format = self.report_format_cb.get()
        self.log_output.delete("1.0", tk.END)
        self.status_label.config(text="Scansione in corso...")
        self.progress_bar['value'] = 0

        selected_modules = []
        modules = get_default_modules(options.get("thorough"))
        for module_name, module_func in modules:
            if self.module_vars.get(module_name) and self.module_vars[module_name].get():
                selected_modules.append((module_name, module_func))
        if options.get("keyword"):
            selected_modules.append(("File Search", lambda: get_file_search_info(options["keyword"])))
            
        t = threading.Thread(target=self.scan_thread, args=(options, selected_modules, report_format), daemon=True)
        t.start()

    def stop_scan(self):
        self.cancel_event.set()
        self.status_label.config(text="Richiesta di interruzione in corso...")
        self.stop_btn.config(state=tk.DISABLED)

    def scan_thread(self, options, selected_modules, report_format):
        results = run_scan(options, selected_modules, report_format)
        self.log_output.insert(tk.END, results)
        self.status_label.config(text="Scansione completata")
        self.progress_bar['value'] = 100
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

# ---------------------------
# FUNZIONE PRINCIPALE
# ---------------------------
def main():
    app = PySecScopeGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
