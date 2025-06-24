#!/usr/bin/env python3
"""
PySecScope v3 - Python Security Scope
Un tool di enumeration per sistemi Linux, con GUI Tkinter, ispirato a LinEnum.
Versione aggiornata con gestione dei moduli (plugin), report in Text/JSON,
progress bar aggiornata, e la possibilità di interrompere la scansione.
"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import json
from datetime import datetime

# ---------------------------
# UTILITÀ: Esecuzione comandi
# ---------------------------
def run_command(cmd):
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return output
    except subprocess.CalledProcessError as e:
        return f"Errore: {e.output}"

# ---------------------------
# FUNZIONI DI SCANSIONE DI BASE
# ---------------------------
def get_system_info():
    info = "==== SYSTEM INFO ====\n" + run_command("uname -a") + "\n"
    try:
        for f in os.listdir("/etc"):
            if "release" in f.lower() or "version" in f.lower():
                try:
                    with open(os.path.join("/etc", f), "r") as file:
                        info += f"--- {f} ---\n" + file.read() + "\n"
                except Exception:
                    continue
    except Exception:
        info += "Impossibile leggere file di release.\n"
    return info

def get_user_info():
    info = "==== USER INFO ====\n" + run_command("id") + "\n"
    try:
        with open("/etc/passwd", "r") as f:
            info += "\n--- /etc/passwd ---\n" + f.read() + "\n"
    except Exception:
        info += "Impossibile leggere /etc/passwd\n"
    return info

def get_network_info():
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
    except Exception:
        info += "Impossibile leggere /etc/resolv.conf\n"
    return info

def get_services_info():
    info = "==== SERVICES INFO ====\n" + "\n--- Processi Correnti (ps aux) ---\n" + run_command("ps aux") + "\n"
    out = run_command("netstat -tulpn")
    if not out.strip():
        out = run_command("ss -tulpn")
    info += "\n--- Porte in Ascolto ---\n" + out + "\n"
    return info

def search_keyword_in_files(keyword, file_pattern, max_depth=4):
    cmd = f"find / -maxdepth {max_depth} -type f -name '{file_pattern}' -exec grep -Hn '{keyword}' {{}} \\; 2>/dev/null"
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
    except Exception:
        info += "Impossibile controllare /proc/1/environ per LXC.\n"
    return info

def get_suid_info():
    cmd = "find / -perm -4000 -type f 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SUID trovato.\n"
    else:
        return "==== SUID FILES ====\n" + output + "\n"

def get_sgid_info():
    cmd = "find / -perm -2000 -type f 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SGID trovato.\n"
    else:
        return "==== SGID FILES ====\n" + output + "\n"

def get_capabilities_info():
    output = run_command("getcap -r / 2>/dev/null")
    if not output.strip():
        return "Nessun file con capabilities POSIX trovato.\n"
    else:
        return "==== FILES WITH CAPABILITIES ====\n" + output + "\n"

def get_plan_files():
    output = run_command("find /home -iname '*.plan' -exec ls -la {} \\; 2>/dev/null")
    if output.strip():
        return "==== Plan Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .plan trovato in /home.\n"

def get_rhosts_files():
    output = run_command("find /home -iname '*.rhosts' -exec ls -la {} \\; 2>/dev/null")
    if output.strip():
        return "==== .rhosts Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .rhosts trovato in /home.\n"

def get_bash_history():
    output = run_command("find /home -name '.bash_history' -exec ls -la {} \\; -exec cat {} \\; 2>/dev/null")
    if output.strip():
        return "==== .bash_history Files in /home ====\n" + output + "\n"
    else:
        return "Nessun file .bash_history accessibile in /home.\n"

def get_bak_files():
    output = run_command("find / -iname '*.bak' -type f 2>/dev/null")
    if output.strip():
        return "==== .bak Files ====\n" + output + "\n"
    else:
        return "Nessun file .bak trovato.\n"

def get_mail_info():
    info = "==== MAIL INFO ====\n" + run_command("ls -la /var/mail") + "\n"
    root_mail = run_command("head /var/mail/root")
    if root_mail.strip():
        info += "\n--- /var/mail/root (snippet) ---\n" + root_mail + "\n"
    return info

# Nuovi moduli aggiunti
def get_cron_jobs_info():
    try:
        crontab = run_command("cat /etc/crontab")
        cron_spool = run_command("ls -la /var/spool/cron 2>/dev/null")
        cron_info = "---- /etc/crontab ----\n" + crontab + "\n---- /var/spool/cron ----\n" + cron_spool
        return "==== CRON JOBS INFO ====\n" + cron_info + "\n"
    except Exception as e:
        return f"Errore nella lettura dei cron jobs: {e}\n"

def get_sudoers_info():
    try:
        sudoers = run_command("cat /etc/sudoers 2>/dev/null")
        if not sudoers.strip():
            return "Non è possibile leggere /etc/sudoers o il file è vuoto.\n"
        return "==== SUDOERS INFO ====\n" + sudoers + "\n"
    except Exception as e:
        return f"Errore nella lettura di /etc/sudoers: {e}\n"

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
            ("Sudoers Info", get_sudoers_info)
        ])
    return modules

# ---------------------------
# FUNZIONE DI SCANSIONE AGGREGATA CON MODULI
# ---------------------------
def run_scan(options, selected_modules, report_format="Text"):
    # Se il report è in JSON, raccogliamo i risultati in un dizionario.
    if report_format == "JSON":
        results_dict = {}
    else:
        results_str = ""
        
    num_modules = len(selected_modules)
    progress_counter = 0
    
    for module_name, module_func in selected_modules:
        # Se la scansione è stata interrotta, fermiamo il processo.
        if options["cancel_event"].is_set():
            if report_format == "JSON":
                results_dict["Interrupted"] = "La scansione è stata interrotta dall'utente."
            else:
                results_str += "\nLa scansione è stata interrotta dall'utente.\n"
            break
        
        result = module_func()
        if report_format == "JSON":
            results_dict[module_name] = result
        else:
            results_str += f"===== {module_name} =====\n{result}\n"
        progress_counter += 1
        options["progress_callback"](progress_counter, num_modules)
    
    final_result = json.dumps(results_dict, indent=4) if report_format == "JSON" else results_str
    
    # Export del report se specificato.
    if options.get("export"):
        try:
            now = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            export_dir = options.get("export")
            ext = "json" if report_format == "JSON" else "txt"
            filename = os.path.join(export_dir, f"PySecScope_report_{now}.{ext}")
            with open(filename, "w") as f:
                f.write(final_result)
            final_result += "\nReport esportato in: " + filename + "\n"
        except Exception as e:
            final_result += "\nErrore durante l'esportazione del report: " + str(e) + "\n"
    
    return final_result

# ---------------------------
# INTERFACCIA GRAFICA CON TKINTER
# ---------------------------
class PySecScopeGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PySecScope v3 - Python Security Scope")
        self.geometry("950x750")
        self.cancel_event = threading.Event()  # Per gestire l'interruzione della scansione
        self.create_widgets()

    def create_widgets(self):
        # Frame per le opzioni generali
        options_frame = ttk.LabelFrame(self, text="Opzioni")
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        # Campo per la keyword
        ttk.Label(options_frame, text="Keyword:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=2)
        self.keyword_entry = ttk.Entry(options_frame, width=30)
        self.keyword_entry.grid(column=1, row=0, padx=5, pady=2)

        # Campo per la directory di export
        ttk.Label(options_frame, text="Export Directory:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=2)
        self.export_entry = ttk.Entry(options_frame, width=30)
        self.export_entry.grid(column=1, row=1, padx=5, pady=2)
        export_btn = ttk.Button(options_frame, text="Sfoglia", command=self.browse_export_dir)
        export_btn.grid(column=2, row=1, padx=5, pady=2)

        # Checkbox per modalità thorough
        self.thorough_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Modalità Thorough", variable=self.thorough_var).grid(column=0, row=2, padx=5, pady=2)

        # Combobox per selezione formato report
        ttk.Label(options_frame, text="Formato Report:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=2)
        self.report_format_cb = ttk.Combobox(options_frame, values=["Text", "JSON"], state="readonly", width=10)
        self.report_format_cb.current(0)
        self.report_format_cb.grid(column=1, row=3, padx=5, pady=2)

        # Frame per la selezione dei moduli
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

        # Frame per i pulsanti di Azione
        action_frame = ttk.Frame(self)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        self.start_btn = ttk.Button(action_frame, text="Avvia Scansione", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = ttk.Button(action_frame, text="Stop Scansione", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Progress Bar e stato
        self.progress_bar = ttk.Progressbar(self, orient='horizontal', mode='determinate', length=300)
        self.progress_bar.pack(padx=10, pady=5)
        self.status_label = ttk.Label(self, text="Pronto")
        self.status_label.pack(padx=10, pady=5)

        # Area di output
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

    def start_scan(self):
        # Resetto il flag di cancellazione
        self.cancel_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        options = {
            "keyword": self.keyword_entry.get().strip(),
            "export": self.export_entry.get().strip(),
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

        # Se è presente una keyword, aggiungo il modulo di File Search.
        if options.get("keyword"):
            selected_modules.append(("File Search", lambda: get_file_search_info(options["keyword"])))
        
        thread = threading.Thread(target=self.scan_thread, args=(options, selected_modules, report_format), daemon=True)
        thread.start()

    def stop_scan(self):
        # Imposto il flag di cancellazione per interrompere la scansione
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
