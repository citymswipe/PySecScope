#!/usr/bin/env python3
"""
PySecScope - Python Security Scope
Un tool di enumeration per sistemi Linux, con GUI Tkinter, ispirato a LinEnum.
"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

# ---------------------------
# FUNZIONI DI UTILITÀ
# ---------------------------
def run_command(cmd):
    """
    Esegue un comando shell e restituisce l’output (o l’errore).
    Se il comando fallisce, l’output dell’eccezione viene restituito.
    """
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return output
    except subprocess.CalledProcessError as e:
        return f"Errore: {e.output}"

# ---------------------------
# FUNZIONI DI RACCOLTA INFORMAZIONI
# ---------------------------
def get_system_info():
    info = "==== SYSTEM INFO ====\n"
    info += run_command("uname -a") + "\n"
    # Legge alcuni file di release (es. /etc/os-release, /etc/lsb-release, etc.)
    try:
        for f in os.listdir("/etc"):
            if "release" in f.lower() or "version" in f.lower():
                try:
                    with open(os.path.join("/etc", f), "r") as file:
                        info += f"--- {f} ---\n" + file.read() + "\n"
                except Exception:
                    continue
    except Exception:
        info += "Impossibile leggere i file di release.\n"
    return info

def get_user_info():
    info = "==== USER INFO ====\n"
    info += run_command("id") + "\n"
    # Tentativo di lettura di /etc/passwd
    try:
        with open("/etc/passwd", "r") as f:
            info += "\n--- /etc/passwd ---\n" + f.read() + "\n"
    except Exception:
        info += "Impossibile leggere /etc/passwd\n"
    return info

def get_network_info():
    info = "==== NETWORK INFO ====\n"
    # Utilizza 'ip a' se disponibile, altrimenti ifconfig
    net_info = run_command("ip a")
    if not net_info.strip():
        net_info = run_command("ifconfig -a")
    info += net_info + "\n"
    info += "\n--- ARP ---\n" + run_command("arp -a") + "\n"
    info += "\n--- Default Route ---\n" + run_command("ip route") + "\n"
    # Legge i nameserver da /etc/resolv.conf
    try:
        with open("/etc/resolv.conf", "r") as f:
            info += "\n--- /etc/resolv.conf ---\n" + f.read() + "\n"
    except Exception:
        info += "Impossibile leggere /etc/resolv.conf\n"
    return info

def get_services_info():
    info = "==== SERVICES INFO ====\n"
    info += "\n--- Processi Correnti (ps aux) ---\n" + run_command("ps aux") + "\n"
    netstat_info = run_command("netstat -tulpn")
    if not netstat_info.strip():
        netstat_info = run_command("ss -tulpn")
    info += "\n--- Porte in Ascolto ---\n" + netstat_info + "\n"
    return info

def search_keyword_in_files(keyword, file_pattern, max_depth=4):
    """
    Utilizza il comando find per cercare file (file_pattern) fino a una certa profondità (max_depth)
    ed eseguire grep per la keyword.
    """
    cmd = f"find / -maxdepth {max_depth} -type f -name '{file_pattern}' -exec grep -Hn '{keyword}' {{}} \\; 2>/dev/null"
    result = run_command(cmd)
    if not result.strip():
        result = f"Nessuna corrispondenza per '{keyword}' in file {file_pattern}\n"
    return result

def get_file_search_info(keyword):
    info = "==== FILE SEARCH (Keyword) ====\n"
    for ext, depth in [("*.conf", 4), ("*.php", 10), ("*.log", 4), ("*.ini", 4)]:
        info += f"\n--- Ricerca in file {ext} ---\n"
        info += search_keyword_in_files(keyword, ext, depth) + "\n"
    return info

def container_checks():
    info = "==== CONTAINER CHECKS ====\n"
    # Controllo Docker tramite /proc/self/cgroup
    docker_check = run_command("grep -i docker /proc/self/cgroup")
    if docker_check.strip():
        info += "Docker container rilevato:\n" + docker_check + "\n"
    else:
        info += "Non in un Docker container.\n"
    # Controlla se esiste il file /.dockerenv
    if os.path.exists("/.dockerenv"):
        info += "Trovato '/.dockerenv': probabilmente in Docker.\n"
    # Controllo per LXC tramite /proc/1/environ
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
    """
    Utilizza il comando find per cercare i file con il bit SUID settato.
    """
    cmd = "find / -perm -4000 -type f 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SUID trovato.\n"
    else:
        info = "==== SUID FILES ====\n" + output + "\n"
        return info

def get_sgid_info():
    """
    Utilizza il comando find per cercare i file con il bit SGID settato.
    """
    cmd = "find / -perm -2000 -type f 2>/dev/null"
    output = run_command(cmd)
    if not output.strip():
        return "Nessun file SGID trovato.\n"
    else:
        info = "==== SGID FILES ====\n" + output + "\n"
        return info

def get_capabilities_info():
    """
    Utilizza il comando getcap per elencare i file con capabilities POSIX.
    """
    output = run_command("getcap -r / 2>/dev/null")
    if not output.strip():
        return "Nessun file con capabilities POSIX trovato.\n"
    else:
        info = "==== FILES WITH CAPABILITIES ====\n" + output + "\n"
        return info

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
    info = "==== MAIL INFO ====\n"
    info += run_command("ls -la /var/mail") + "\n"
    root_mail = run_command("head /var/mail/root")
    if root_mail.strip():
        info += "\n--- /var/mail/root (snippet) ---\n" + root_mail + "\n"
    return info

# ---------------------------
# FUNZIONE DI SCANSIONE AGGREGATA
# ---------------------------
def run_scan(options):
    results = ""
    results += "***** PySecScope Scan Started *****\n\n"
    results += get_system_info() + "\n"
    results += get_user_info() + "\n"
    results += get_network_info() + "\n"
    results += get_services_info() + "\n"
    
    # Se l'utente ha specificato una keyword, esegue la ricerca in file specifici.
    if options.get("keyword"):
        results += get_file_search_info(options["keyword"]) + "\n"
    
    # Se la modalità thorough è attivata, esegue controlli aggiuntivi.
    if options.get("thorough"):
        results += "\n--- Modalità Thorough Abilitata ---\n"
        results += get_suid_info() + "\n"
        results += get_sgid_info() + "\n"
        results += get_capabilities_info() + "\n"
        results += get_plan_files() + "\n"
        results += get_rhosts_files() + "\n"
        results += get_bash_history() + "\n"
        results += get_bak_files() + "\n"
        results += get_mail_info() + "\n"
    
    results += container_checks() + "\n"
    results += "***** PySecScope Scan Completed *****\n"
    
    # Esportazione del report se è stata fornita una directory di export.
    if options.get('export'):
        try:
            now = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            export_dir = options.get('export')
            filename = os.path.join(export_dir, f"PySecScope_report_{now}.txt")
            with open(filename, "w") as f:
                f.write(results)
            results += "\nReport esportato in: " + filename + "\n"
        except Exception as e:
            results += "\nErrore durante l'esportazione del report: " + str(e) + "\n"
    
    return results

# ---------------------------
# INTERFACCIA GRAFICA CON TKINTER
# ---------------------------
class PySecScopeGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PySecScope - Python Security Scope")
        self.geometry("900x600")
        self.create_widgets()

    def create_widgets(self):
        # Frame per le opzioni
        options_frame = ttk.LabelFrame(self, text="Opzioni")
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        # Campo per inserire la keyword
        ttk.Label(options_frame, text="Keyword:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=2)
        self.keyword_entry = ttk.Entry(options_frame, width=30)
        self.keyword_entry.grid(column=1, row=0, padx=5, pady=2)

        # Campo per la directory di export
        ttk.Label(options_frame, text="Export Directory:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=2)
        self.export_entry = ttk.Entry(options_frame, width=30)
        self.export_entry.grid(column=1, row=1, padx=5, pady=2)
        export_btn = ttk.Button(options_frame, text="Sfoglia", command=self.browse_export_dir)
        export_btn.grid(column=2, row=1, padx=5, pady=2)

        # Checkbox per la modalità thorough
        self.thorough_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Modalità Thorough", variable=self.thorough_var).grid(column=0, row=2, padx=5, pady=2)

        # Pulsante per avviare la scansione
        scan_btn = ttk.Button(options_frame, text="Avvia Scansione", command=self.start_scan)
        scan_btn.grid(column=1, row=3, padx=5, pady=5)

        # Area di log / output
        self.log_output = ScrolledText(self, wrap=tk.WORD, height=25)
        self.log_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

    def browse_export_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.export_entry.delete(0, tk.END)
            self.export_entry.insert(0, directory)

    def start_scan(self):
        options = {
            "keyword": self.keyword_entry.get().strip(),
            "export": self.export_entry.get().strip(),
            "thorough": self.thorough_var.get()
        }
        self.log_output.delete("1.0", tk.END)
        # Avvia la scansione in un thread separato per mantenere responsive l'interfaccia
        thread = threading.Thread(target=self.scan_thread, args=(options,), daemon=True)
        thread.start()

    def scan_thread(self, options):
        self.log_output.insert(tk.END, "Avvio della scansione...\n\n")
        results = run_scan(options)
        self.log_output.insert(tk.END, results)
        self.log_output.insert(tk.END, "\n--- Scansione completata ---\n")

# ---------------------------
# FUNZIONE PRINCIPALE
# ---------------------------
def main():
    app = PySecScopeGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
