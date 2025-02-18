import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
from subprocess import Popen, PIPE
import getpass
import re
from datetime import datetime
from PIL import Image, ImageTk
import json

class AntGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Autonomi Network GUI")
        
        # Setup history file paths
        self.history_dir = os.path.expanduser("~/.local/share/autonomi/client/gui")
        self.operations_file = os.path.join(self.history_dir, "operations_history.txt")
        self.uploads_file = os.path.join(self.history_dir, "file_uploads.json")
        
        # Create directory if it doesn't exist
        os.makedirs(self.history_dir, exist_ok=True)
        
        # Initialize history tracking
        self.operation_history = []
        self.file_uploads = {}
        
        # Load saved history
        self.load_history()
        
        # Add status notification variable and counter
        self.status_var = tk.StringVar()
        self.blink_counter = 0
        
        # Configure root grid to expand
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Create main frame with notebook for tabs
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure main frame grid to expand
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Create Output Text Area first
        self.output_text = tk.Text(main_frame, height=10, width=50)
        self.output_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Scrollbar for output
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.output_text['yscrollcommand'] = scrollbar.set
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create frames for each tab
        register_frame = ttk.Frame(notebook, padding="5")
        key_frame = ttk.Frame(notebook, padding="5")
        vault_frame = ttk.Frame(notebook, padding="5")
        wallet_frame = ttk.Frame(notebook, padding="5")
        file_frame = ttk.Frame(notebook, padding="5")
        history_frame = ttk.Frame(notebook, padding="5")
        about_frame = ttk.Frame(notebook, padding="5")
        
        # Configure all frames to expand
        for frame in (register_frame, key_frame, vault_frame, wallet_frame, 
                     file_frame, history_frame, about_frame):
            frame.columnconfigure(1, weight=1)
            frame.rowconfigure(0, weight=1)
        
        # Add frames to notebook
        notebook.add(register_frame, text="Register")
        notebook.add(key_frame, text="Keys")
        notebook.add(vault_frame, text="Vaults")
        notebook.add(wallet_frame, text="Wallet")
        notebook.add(file_frame, text="Files")
        notebook.add(history_frame, text="History")
        notebook.add(about_frame, text="About")
        
        # Configure notebook to expand
        notebook.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Setup Register Operations
        self.setup_register_frame(register_frame)
        
        # Setup Key Operations
        self.setup_key_frame(key_frame)
        
        # Setup Wallet Operations
        self.setup_wallet_frame(wallet_frame)
        
        # Setup File Operations
        self.setup_file_frame(file_frame)
        
        # Setup Vault Operations
        self.setup_vault_frame(vault_frame)
        
        # Setup History Operations
        self.setup_history_frame(history_frame)
        
        # Setup About tab
        self.setup_about_frame(about_frame)

    def setup_register_frame(self, frame):
        """Setup Register Operations tab"""
        frame.columnconfigure(1, weight=1)
        
        # Add description label at the top
        description = ("Register and manage human-readable names on the network.\n\n"
                      "When you register a name:\n"
                      "• It creates a unique register with a long hexadecimal address\n"
                      "• The name becomes associated with your chosen value\n"
                      "• A small amount of tokens is required for registration")
        desc_label = ttk.Label(frame, text=description, wraplength=300, justify=tk.LEFT)
        desc_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Register new name
        ttk.Label(frame, text="Register Name:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.register_frame = ttk.Frame(frame)
        self.register_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Add labels above entries
        ttk.Label(self.register_frame, text="Name").grid(
            row=0, column=0, sticky=tk.W, pady=(0, 2))
        ttk.Label(self.register_frame, text="Value").grid(
            row=0, column=1, sticky=tk.W, pady=(0, 2))
        
        self.name_entry = ttk.Entry(self.register_frame)
        self.name_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.value_entry = ttk.Entry(self.register_frame)
        self.value_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.register_button = ttk.Button(self.register_frame, text="Register", 
                                        command=self.register_name)
        self.register_button.grid(row=1, column=2)
        
        # Add key selection for register operation
        ttk.Label(self.register_frame, text="Sign with Key:").grid(
            row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.key_combobox = ttk.Combobox(self.register_frame, state="readonly")
        self.key_combobox.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), 
                              pady=(5, 0), padx=(0, 5))
        self.update_key_list()  # Populate key list
        
        # List registered names
        ttk.Label(frame, text="List Names:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.list_names_button = ttk.Button(frame, text="List All Names", 
                                          command=self.list_names)
        self.list_names_button.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)

    def setup_key_frame(self, frame):
        """Setup Key Operations tab"""
        frame.columnconfigure(1, weight=1)
        
        # Add description
        description = ("Generate and manage keys for registering names.\n"
                      "Keys are required to create and manage registers on the network.")
        desc_label = ttk.Label(frame, text=description, wraplength=300, justify=tk.LEFT)
        desc_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Generate new key
        ttk.Label(frame, text="Generate Key:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.generate_key_frame = ttk.Frame(frame)
        self.generate_key_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        self.overwrite_var = tk.BooleanVar()
        self.overwrite_check = ttk.Checkbutton(self.generate_key_frame, 
                                              text="Overwrite existing", 
                                              variable=self.overwrite_var)
        self.overwrite_check.pack(side=tk.LEFT)
        
        self.generate_key_button = ttk.Button(self.generate_key_frame, 
                                            text="Generate New Key", 
                                            command=self.generate_key)
        self.generate_key_button.pack(side=tk.LEFT, padx=5)

    def setup_wallet_frame(self, frame):
        """Setup Wallet Operations tab"""
        frame.columnconfigure(1, weight=1)  # Make second column expandable
        
        # Wallet Balance
        ttk.Label(frame, text="Wallet Balance:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.balance_frame = ttk.Frame(frame)
        self.balance_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        self.balance_frame.columnconfigure(0, weight=1)  # Make label expand
        
        self.balance_label = ttk.Label(self.balance_frame, text="")
        self.balance_label.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.balance_button = ttk.Button(self.balance_frame, text="Check Balance", 
                                       command=self.check_balance)
        self.balance_button.grid(row=0, column=1)
        
        # Create new wallet
        ttk.Label(frame, text="Create Wallet:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.create_wallet_button = ttk.Button(frame, text="Create New Wallet", 
                                             command=self.create_wallet)
        self.create_wallet_button.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Import MetaMask Wallet
        ttk.Label(frame, text="Import MetaMask:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.import_metamask_button = ttk.Button(frame, text="Import MetaMask Wallet", 
                                               command=self.import_metamask)
        self.import_metamask_button.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)

    def setup_file_frame(self, frame):
        """Setup File Operations tab"""
        frame.columnconfigure(1, weight=1)  # Make second column expandable
        
        # File Cost
        ttk.Label(frame, text="Get File Cost:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.cost_button = ttk.Button(frame, text="Select File & Get Cost", 
                                    command=self.get_file_cost)
        self.cost_button.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Add status label for notifications
        self.status_label = ttk.Label(frame, textvariable=self.status_var, foreground='blue')
        self.status_label.grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # File Upload
        ttk.Label(frame, text="Upload File:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.upload_frame = ttk.Frame(frame)
        self.upload_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        self.upload_frame.columnconfigure(0, weight=1)  # Make button expand
        
        self.upload_button = ttk.Button(self.upload_frame, text="Select & Upload", 
                                      command=self.upload_file)
        self.upload_button.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.public_var = tk.BooleanVar()
        self.public_check = ttk.Checkbutton(frame, text="Public", variable=self.public_var)
        self.public_check.grid(row=1, column=2, sticky=tk.W)
        
        # File Download
        ttk.Label(frame, text="Download File:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.download_frame = ttk.Frame(frame)
        self.download_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)
        self.download_frame.columnconfigure(0, weight=1)  # Make entry expand
        
        self.addr_entry = ttk.Entry(self.download_frame)
        self.addr_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.download_button = ttk.Button(self.download_frame, text="Download", 
                                        command=self.download_file)
        self.download_button.grid(row=0, column=1)
        
        # List Files
        ttk.Label(frame, text="List Files:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.list_button = ttk.Button(frame, text="List All Files", command=self.list_files)
        self.list_button.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)

    def setup_vault_frame(self, frame):
        """Setup Vault Operations tab"""
        frame.columnconfigure(1, weight=1)  # Make second column expandable
        
        # Add description
        description = ("Manage network vaults.\n"
                      "Vaults store and manage network data.\n\n"
                      "1. Create a new vault\n"
                      "2. Start/Stop the vault\n"
                      "3. Monitor vault status")
        desc_label = ttk.Label(frame, text=description, wraplength=300, justify=tk.LEFT)
        desc_label.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Create Vault
        ttk.Label(frame, text="Create Vault:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.create_vault_button = ttk.Button(frame, text="Create New Vault", 
                                            command=self.create_vault)
        self.create_vault_button.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Vault Control
        ttk.Label(frame, text="Vault Control:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.vault_frame = ttk.Frame(frame)
        self.vault_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)
        self.vault_frame.columnconfigure(0, weight=1)  # Make vault frame expandable
        
        # Vault options frame
        self.vault_options_frame = ttk.Frame(self.vault_frame)
        self.vault_options_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.vault_options_frame.columnconfigure(2, weight=1)  # Make space after options expand
        
        # Delay option
        ttk.Label(self.vault_options_frame, text="Delay (secs):").grid(row=0, column=0, padx=5)
        self.delay_var = tk.StringVar(value="0")
        self.delay_entry = ttk.Entry(self.vault_options_frame, textvariable=self.delay_var, width=5)
        self.delay_entry.grid(row=0, column=1, padx=5)
        
        # Local option
        self.local_var = tk.BooleanVar()
        self.local_check = ttk.Checkbutton(self.vault_options_frame, 
                                         text="Local", 
                                         variable=self.local_var)
        self.local_check.grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # Control buttons frame
        self.vault_buttons_frame = ttk.Frame(self.vault_frame)
        self.vault_buttons_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        self.vault_buttons_frame.columnconfigure(2, weight=1)  # Make space between buttons expand
        
        self.start_vault_button = ttk.Button(self.vault_buttons_frame, 
                                           text="Start Vault", 
                                           command=self.start_vault)
        self.start_vault_button.grid(row=0, column=0, padx=5)
        
        self.stop_vault_button = ttk.Button(self.vault_buttons_frame, 
                                          text="Stop Vault", 
                                          command=self.stop_vault)
        self.stop_vault_button.grid(row=0, column=1, padx=5)
        
        # Vault Status
        ttk.Label(frame, text="Vault Status:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.vault_status_button = ttk.Button(frame, text="Check Status", 
                                            command=self.check_vault_status)
        self.vault_status_button.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)

    def setup_history_frame(self, frame):
        """Setup History Operations tab"""
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        
        # Add description
        description = ("Operation History and File Uploads\n"
                      "Track all operations and uploaded files with their addresses")
        desc_label = ttk.Label(frame, text=description, wraplength=300, justify=tk.LEFT)
        desc_label.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Create notebook for sub-tabs
        history_notebook = ttk.Notebook(frame)
        history_notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create sub-frames for operations and files
        operations_frame = ttk.Frame(history_notebook, padding="5")
        files_frame = ttk.Frame(history_notebook, padding="5")
        
        history_notebook.add(operations_frame, text="Operations")
        history_notebook.add(files_frame, text="Uploaded Files")
        
        # Operations History - Make text selectable
        self.operations_text = tk.Text(operations_frame, height=20, width=50)
        self.operations_text.pack(fill=tk.BOTH, expand=True)
        ops_scrollbar = ttk.Scrollbar(operations_frame, orient=tk.VERTICAL, 
                                    command=self.operations_text.yview)
        ops_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.operations_text['yscrollcommand'] = ops_scrollbar.set
        # Allow text selection but prevent editing
        self.operations_text.config(state='disabled', cursor="arrow")
        
        # Files List - Make cells selectable
        self.files_tree = ttk.Treeview(files_frame, 
                                     columns=('Filename', 'Address'), 
                                     show='headings', 
                                     height=20,
                                     selectmode='browse')  # Allow row selection
        self.files_tree.heading('Filename', text='Filename')
        self.files_tree.heading('Address', text='Address')
        self.files_tree.column('Filename', width=150)
        self.files_tree.column('Address', width=400)
        self.files_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar for files tree
        files_scrollbar = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, 
                                      command=self.files_tree.yview)
        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.files_tree.configure(yscrollcommand=files_scrollbar.set)
        
        # Add right-click menu for copying
        self.tree_menu = tk.Menu(self.files_tree, tearoff=0)
        self.tree_menu.add_command(label="Copy Address", 
                                 command=self.copy_selected_address)
        self.tree_menu.add_command(label="Copy Filename", 
                                 command=self.copy_selected_filename)
        self.files_tree.bind("<Button-3>", self.show_tree_menu)

        # Load initial history into UI
        self.operations_text.config(state='normal')
        for entry in self.operation_history:
            self.operations_text.insert(tk.END, entry)
        self.operations_text.config(state='disabled')
        
        # Load initial uploads into UI
        self.files_tree.delete(*self.files_tree.get_children())  # Clear first
        sorted_entries = sorted(self.file_uploads.values(), key=lambda x: x[0])
        for fname, addr in sorted_entries:
            self.files_tree.insert('', tk.END, values=(fname, addr))

    def setup_about_frame(self, frame):
        """Setup About tab"""
        frame.columnconfigure(0, weight=1)
        
        # Load and display the logo
        try:
            # Open and convert JPG image
            image = Image.open("bafkreibxe7zj3gpudnqg5or53ssdxmbagdfmp4khsf56tx3xtw2tafowwq.jpg")
            # Resize image to a reasonable size (e.g., 200x200 pixels)
            image = image.resize((200, 200), Image.Resampling.LANCZOS)
            logo_image = ImageTk.PhotoImage(image)
            
            logo_label = ttk.Label(frame, image=logo_image)
            logo_label.image = logo_image  # Keep a reference to prevent garbage collection
            logo_label.grid(row=0, column=0, pady=(20, 30))
        except Exception as e:
            # If image loading fails, show text instead
            print(f"Failed to load image: {e}")
            ttk.Label(frame, text="Autonomi Front End", 
                     font=('Helvetica', 16, 'bold')).grid(row=0, column=0, pady=(20, 30))
        
        # App information
        info_frame = ttk.Frame(frame)
        info_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=20)
        info_frame.columnconfigure(0, weight=1)
        
        info_text = """Autonomi Front End

A graphical interface for the Autonomi Network CLI

Created by NAFO radio
Licensed under MIT License

Support the development:"""
        
        ttk.Label(info_frame, text=info_text, 
                 justify=tk.CENTER).grid(row=0, column=0, pady=(0, 10))
        
        # Ethereum donation address
        eth_frame = ttk.Frame(info_frame)
        eth_frame.grid(row=1, column=0, pady=(0, 20))
        
        eth_addr = "0x4AcD49Aca41E31aa54f43e3109e7b0dB47369B65"
        ttk.Label(eth_frame, text="ETH: ").pack(side=tk.LEFT)
        
        # Make address selectable
        eth_entry = ttk.Entry(eth_frame, width=42)
        eth_entry.insert(0, eth_addr)
        eth_entry.configure(state='readonly')
        eth_entry.pack(side=tk.LEFT)
        
        # Copy button
        def copy_address():
            frame.clipboard_clear()
            frame.clipboard_append(eth_addr)
            frame.update()  # Required to finalize clipboard
            
        copy_button = ttk.Button(eth_frame, text="Copy", command=copy_address)
        copy_button.pack(side=tk.LEFT, padx=(5, 0))

    def load_history(self):
        """Load operation history and file uploads from disk"""
        # Load operations history
        try:
            if os.path.exists(self.operations_file):
                with open(self.operations_file, 'r') as f:
                    self.operation_history = f.read().splitlines(True)  # Keep the newlines
        except Exception as e:
            print(f"Error loading operations history: {e}")
            self.operation_history = []
        
        # Load file uploads
        try:
            if os.path.exists(self.uploads_file):
                with open(self.uploads_file, 'r') as f:
                    loaded_uploads = json.loads(f.read())
                    # Convert the loaded data to match our internal format
                    for key, value in loaded_uploads.items():
                        if isinstance(value, list):  # Handle old format
                            filename, address = value
                        else:  # Handle tuple stored as array
                            filename, address = value
                        self.file_uploads[key] = (filename, address)
        except Exception as e:
            print(f"Error loading file uploads: {e}")
            self.file_uploads = {}

    def save_history(self):
        """Save operation history and file uploads to disk"""
        # Save operations history
        try:
            with open(self.operations_file, 'w') as f:
                f.writelines(self.operation_history)
        except Exception as e:
            print(f"Error saving operations history: {e}")
        
        # Save file uploads
        try:
            # Convert tuples to lists for JSON serialization
            uploads_to_save = {k: list(v) for k, v in self.file_uploads.items()}
            with open(self.uploads_file, 'w') as f:
                json.dump(uploads_to_save, f, indent=2)
        except Exception as e:
            print(f"Error saving file uploads: {e}")

    def add_to_history(self, command, output):
        """Add an operation to history and save"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}]\nCommand: {' '.join(command)}\nOutput:\n{output}\n"
        entry += "-" * 50 + "\n"
        
        self.operation_history.append(entry)
        self.operations_text.config(state='normal')
        self.operations_text.insert(tk.END, entry)
        self.operations_text.see(tk.END)
        self.operations_text.config(state='disabled')
        
        # Save after each operation
        self.save_history()

    def add_file_upload(self, filename, address):
        """Add a file upload to the tracking system and save"""
        # Use both filename and type (Public/Private) as the key
        file_type = address.split(':')[0]  # Get 'Public' or 'Private'
        key = f"{filename}_{file_type}"
        
        self.file_uploads[key] = (filename, address)
        self.files_tree.delete(*self.files_tree.get_children())  # Clear current entries
        
        # Sort entries to group files together
        sorted_entries = sorted(self.file_uploads.values(), key=lambda x: x[0])
        for fname, addr in sorted_entries:
            self.files_tree.insert('', tk.END, values=(fname, addr))
        
        # Save after each upload
        self.save_history()

    def run_ant_command(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            
            # Add to history
            self.add_to_history(command, output)
            
            # If this was a file upload or list command, try to extract the addresses
            if (len(command) >= 3 and 
                command[1] == 'file' and 
                (command[2] == 'upload' or command[2] == 'list')):
                
                # Clear existing entries if this is a list command
                if command[2] == 'list':
                    self.file_uploads.clear()
                
                lines = output.split('\n')
                current_type = None
                
                for line in lines:
                    if 'public file archive' in line:
                        current_type = 'Public'
                        continue
                    elif 'private file archive' in line:
                        current_type = 'Private'
                        continue
                    
                    # Look for any line with bafkreib and a colon
                    if current_type and 'bafkreib' in line and ':' in line:
                        try:
                            filename, address = line.strip().split(': ')
                            if filename and address:
                                self.add_file_upload(filename, f"{current_type}: {address}")
                        except ValueError:
                            continue
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {error_msg}")
            self.add_to_history(command, f"Error: {error_msg}")

    def blink_status(self, message, times=6):
        """Blinks the status message specified number of times"""
        if self.blink_counter < times:
            if self.blink_counter % 2 == 0:
                self.status_var.set(message)
            else:
                self.status_var.set("")
            self.blink_counter += 1
            self.root.after(500, lambda: self.blink_status(message, times))
        else:
            self.status_var.set("")
            self.blink_counter = 0

    def get_file_cost(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.blink_status("Calculating cost...")
            self.run_ant_command(['ant', 'file', 'cost', file_path])

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            command = ['ant', 'file', 'upload', file_path]
            if self.public_var.get():
                command.append('--public')
            self.run_ant_command(command)

    def download_file(self):
        addr = self.addr_entry.get().strip()
        if not addr:
            messagebox.showerror("Error", "Please enter a file address")
            return
        
        save_path = filedialog.asksaveasfilename()
        if save_path:
            self.run_ant_command(['ant', 'file', 'download', addr, save_path])

    def list_files(self):
        self.run_ant_command(['ant', 'file', 'list'])

    def check_balance(self):
        """Check wallet balance"""
        # Show message to user
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Please enter your wallet password in the terminal...")
        self.output_text.update()  # Force update to show message immediately
        
        try:
            # Run command normally - password prompt will appear in terminal
            result = subprocess.run(['ant', 'wallet', 'balance'], 
                                  capture_output=True,  # Capture the output
                                  text=True)
            
            if result.returncode == 0:
                # Update both the label and output text with the balance
                balance = result.stdout.strip()
                self.balance_label.config(text=balance)
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, f"Current balance: {balance}")
            else:
                self.balance_label.config(text="Error")
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, f"Error: {result.stderr}")
                
        except Exception as e:
            self.balance_label.config(text="Error")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    def register_name(self):
        name = self.name_entry.get().strip()
        value = self.value_entry.get().strip()
        key = self.key_combobox.get()
        
        if not all([name, value]):
            messagebox.showerror("Error", "Please enter both name and value")
            return
            
        if not key:
            messagebox.showerror("Error", "No signing key found. Please generate a key first.")
            return
            
        # The key path is used directly in the register command
        self.run_ant_command(['ant', 'register', 'create', name, value])

    def list_names(self):
        self.run_ant_command(['ant', 'register', 'list'])

    def create_wallet(self):
        self.run_ant_command(['ant', 'wallet', 'create'])

    def import_metamask(self):
        """Import MetaMask wallet"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Please enter your MetaMask seed phrase in the terminal...")
        self.output_text.update()
        
        try:
            result = subprocess.run(['ant', 'wallet', 'import'], 
                                  capture_output=True,
                                  text=True)
            
            if result.returncode == 0:
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, "MetaMask wallet imported successfully")
            else:
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, f"Error: {result.stderr}")
                
        except Exception as e:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    # New key-related methods
    def generate_key(self):
        """Generate a new register key"""
        command = ['ant', 'register', 'generate-key']
        if self.overwrite_var.get():
            command.append('--overwrite')
        self.run_ant_command(command)
        self.update_key_list()

    def update_key_list(self):
        """Update the key selection combobox with the register signing key"""
        key_path = os.path.expanduser("~/.local/share/autonomi/client/register_signing_key")
        
        if os.path.exists(key_path):
            # The key exists, add it to the combobox
            self.key_combobox['values'] = ["register_signing_key"]
            self.key_combobox.set("register_signing_key")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "Found register signing key")
        else:
            # No key found
            self.key_combobox['values'] = []
            self.key_combobox.set("")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "No register signing key found. Please generate a key first.")

    def start_vault(self):
        """Start a vault with specified options"""
        command = ['ant', 'vault', 'start']
        
        # Add delay if specified
        delay = self.delay_var.get().strip()
        if delay and delay != "0":
            command.extend(['--delay', delay])
            
        # Add local flag if checked
        if self.local_var.get():
            command.append('--local')
            
        self.run_ant_command(command)

    def stop_vault(self):
        """Stop the vault"""
        self.run_ant_command(['ant', 'vault', 'stop'])

    def check_vault_status(self):
        """Check vault status"""
        self.run_ant_command(['ant', 'vault', 'status'])

    def create_vault(self):
        """Create a new vault"""
        self.run_ant_command(['ant', 'vault', 'create'])

    def show_tree_menu(self, event):
        """Show context menu for tree items"""
        item = self.files_tree.identify_row(event.y)
        if item:
            self.files_tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def copy_selected_address(self):
        """Copy the address of the selected file"""
        selection = self.files_tree.selection()
        if selection:
            item = selection[0]
            address = self.files_tree.item(item)['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
            self.root.update()

    def copy_selected_filename(self):
        """Copy the filename of the selected file"""
        selection = self.files_tree.selection()
        if selection:
            item = selection[0]
            filename = self.files_tree.item(item)['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(filename)
            self.root.update()

def main():
    root = tk.Tk()
    app = AntGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 