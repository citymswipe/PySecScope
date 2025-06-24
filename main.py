class PySecScopeGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PySecScope - Python Security Scope")
        self.geometry("900x650")
        self.create_widgets()

    def create_widgets(self):
        # Frame per le opzioni
        options_frame = ttk.LabelFrame(self, text="Opzioni")
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        # Campo per la keyword
        ttk.Label(options_frame, text="Keyword:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=2)
        self.keyword_entry = ttk.Entry(options_frame, width=30)
        self.keyword_entry.grid(column=1, row=0, padx=5, pady=2)

        # Campo per l’export directory
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

        # Progress Bar per indicare l'avanzamento
        self.progress_bar = ttk.Progressbar(self, orient='horizontal',
                                            mode='indeterminate', length=200)
        self.progress_bar.pack(padx=10, pady=5)

        # Area di log / output
        self.log_output = ScrolledText(self, wrap=tk.WORD, height=25)
        self.log_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Etichetta di stato
        self.status_label = ttk.Label(self, text="Pronto")
        self.status_label.pack(padx=10, pady=2)

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
        self.status_label.config(text="Scansione in corso...")
        self.progress_bar.start(10)  # Avvia la progress bar con aggiornamenti ogni 10ms
        thread = threading.Thread(target=self.scan_thread, args=(options,), daemon=True)
        thread.start()

    def scan_thread(self, options):
        results = run_scan(options)
        self.log_output.insert(tk.END, results)
        self.log_output.insert(tk.END, "\n--- Scansione completata ---\n")
        self.status_label.config(text="Scansione completata")
        self.progress_bar.stop()
