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

# Funzione di utilità per eseguire comandi e restituire output
def run_command(cmd):
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return output
    except subprocess.CalledProcessError as e:
        return f"Errore: {e.output}"

# Funzioni di raccolta informazioni

def get_system_info():
    info = "==== SYSTEM INFO ====\n"
    info += run_command("uname -a") + "\n"
    # Legge informazioni dai file di release (es. /etc/os-release o altri)
    try:
        for f in os.listdir("/etc"):
            if "release" in f:
                with open(os.path.join("/etc", f), "r") as file:
                    info += f"--- {f} ---\n" + file.read() + "\n"
    except Exception as e:
        info += "Impossibile leggere file di release\n"
    return info

def get_user_info():
    info = "==== USER INFO ====\n"
    info += run_command("id") + "\n"
    # Prova a leggere /etc/passwd (se accessibile)
    try:
        with open("/etc/passwd", "r") as f:
            info += "\n--- /etc/passwd ---\n" + f.read() + "\n"
    except Exception as e:
        info += "Impossibile leggere /etc/passwd\n"
    return info

def get_network_info():
    info = "==== NETWORK INFO ====\n"
    # Utilizza 'ip a', se non disponibile 'ifconfig -a'
    net_info = run_command("ip a")
    if not net_info.strip():
        net_info = run_command("ifconfig -a")
    info += net_info + "\n"
    info += "\n--- ARP ---\n" + run_command("arp -a") + "\n"
    info += "\n--- Default Route ---\n" + run_command("ip route") + "\n"
    return info

def get_services_info():
    info = "==== SERVICES INFO ====\n"
    info += "\n--- Processi Correnti (ps aux) ---\n" + run_command("ps aux") + "\n"
    netstat_info = run_command("netstat -tulpn")
    if not netstat_info.strip():
        netstat_info = run_command("ss -tulpn")
    info += "\n--- Porte in Ascolto ---\n" + netstat_info + "\n"
    return info

# Funzione per eseguire ricerche nei file tramite keyword
def search_keyword_in_files(keyword, file_pattern, max_depth=4):
    # Utilizza il comando find per cercare file corrispondenti e grep per la keyword
    cmd = f"find / -maxdepth {max_depth} -type f -name '{file_pattern}' -exec grep -Hn '{keyword}' {{}} \\;"
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
    except Exception as e:
        info += "Impossibile controllare /proc/1/environ per LXC.\n"
    return info

# Funzione di scansione aggregata che combina le sezioni
def run_scan(options):
    results = ""
    results += "***** PySecScope Scan Started *****\n\n"
    results += get_system_info() + "\n"
    results += get_user_info() + "\n"
    results += get_network_info() + "\n"
    results += get_services_info() + "\n"
    if options.get("keyword"):
        results += get_file_search_info(options["keyword"]) + "\n"
    if options.get("thorough"):
        results += "Modalità Thorough abilitata: ulteriori controlli possono essere implementati...\n"
        # Qui si potrebbero aggiungere funzioni extra (ad es. ricerca SUID/SGID, capabilities, ecc.)
    results += container_checks() + "\n"
    results += "***** PySecScope Scan Completed *****\n"
    return results

# --- Interfaccia Grafica Tkinter ---

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

        # Pulsante per avviare la scansione
        scan_btn = ttk.Button(options_frame, text="Avvia Scansione", command=self.start_scan)
        scan_btn.grid(column=1, row=3, padx=5, pady=5)

        # Area testuale per mostrare i log e i risultati
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
        # Esegue la scansione in un thread per non bloccare l'interfaccia
        thread = threading.Thread(target=self.scan_thread, args=(options,), daemon=True)
        thread.start()

    def scan_thread(self, options):
        self.log_output.insert(tk.END, "Avvio della scansione...\n\n")
        results = run_scan(options)
        self.log_output.insert(tk.END, results)
        self.log_output.insert(tk.END, "\n--- Scansione completata ---\n")

def main():
    app = PySecScopeGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
