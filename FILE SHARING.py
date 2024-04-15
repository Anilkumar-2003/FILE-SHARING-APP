import tkinter as tk
from tkinter import filedialog, messagebox
import shutil
import os
from cryptography.fernet import Fernet

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("300x150")

        self.username_label = tk.Label(self.root, text="Username:")
        self.username_label.pack()

        self.username_entry = tk.Entry(self.root, width=30)  # Increased width
        self.username_entry.pack()

        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(self.root, show="*", width=30)  # Increased width
        self.password_entry.pack()

        self.login_button = tk.Button(self.root, text="Login", command=self.authenticate)
        self.login_button.pack()

        # Initialize authorized users
        self.authorized_users = {
            "user1": "password1",
            "user2": "password2",
            "pandu": "123456",
            "anil": "AD1234"
        }

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.authorized_users and self.authorized_users[username] == password:
            self.root.destroy()
            FileShareApp(tk.Tk())
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

class FileShareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Sharing App")

        # Generate a key for encryption
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

        # Create main container frame
        self.main_frame = tk.Frame(self.root, bg="#e0e0e0")
        self.main_frame.pack(padx=20, pady=20)

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # File selection button
        self.file_label = tk.Label(self.main_frame, text="Select File(s) to Share:", font=("Arial", 12), bg="#e0e0e0")
        self.file_label.grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.file_entry = tk.Entry(self.main_frame, width=30, font=("Arial", 10))
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        self.browse_button = tk.Button(self.main_frame, text="Browse", command=self.browse_files, font=("Arial", 10), bg="#d3d3d3")
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)

        # Folder selection button
        self.folder_label = tk.Label(self.main_frame, text="Select Folder:", font=("Arial", 12), bg="#e0e0e0")
        self.folder_label.grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.folder_entry = tk.Entry(self.main_frame, width=30, font=("Arial", 10))
        self.folder_entry.grid(row=1, column=1, padx=5, pady=5)
        self.folder_button = tk.Button(self.main_frame, text="Select Folder", command=self.select_folder, font=("Arial", 10), bg="#d3d3d3")
        self.folder_button.grid(row=1, column=2, padx=5, pady=5)

        # Manage Files Label
        self.manage_files_label = tk.Label(self.main_frame, text="Manage Files:", font=("Arial", 14, "bold"), bg="#e0e0e0")
        self.manage_files_label.grid(row=2, column=0, columnspan=3, pady=10)

        # Listbox to display uploaded files
        self.file_listbox = tk.Listbox(self.main_frame, width=50, height=8, font=("Arial", 10))
        self.file_listbox.grid(row=3, column=0, columnspan=3, pady=5)

        # View, Organize, Delete buttons
        self.view_button = tk.Button(self.main_frame, text="View Files", command=self.view_files, font=("Arial", 12), bg="yellow", fg="black")
        self.view_button.grid(row=4, column=0, padx=5, pady=5)  # Yellow color

        self.organize_button = tk.Button(self.main_frame, text="Organize Files", command=self.organize_files, font=("Arial", 12), bg="#FFB6C1")
        self.organize_button.grid(row=4, column=1, padx=5, pady=5)  # Light pink color

        self.delete_button = tk.Button(self.main_frame, text="Delete File", command=self.delete_file, font=("Arial", 12), bg="#29c4F6")
        self.delete_button.grid(row=4, column=2, padx=5, pady=5)

        # Share button
        self.share_button = tk.Button(self.main_frame, text="Share", command=self.upload_files, font=("Arial", 12), bg="#4caf50", fg="white")
        self.share_button.grid(row=5, column=0, columnspan=3, pady=10)

    def browse_files(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, "\n".join(file_paths))

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder_path)

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        return encrypted_data

    def decrypt_file(self, encrypted_data, destination_path):
        decrypted_data = self.fernet.decrypt(encrypted_data)
        with open(destination_path, 'wb') as f:
            f.write(decrypted_data)

    def upload_files(self):
        file_paths = self.file_entry.get().split("\n")
        if not file_paths:
            messagebox.showerror("Error", "Please select file(s) to share.")
            return

        shared_folder = "shared"
        if not os.path.exists(shared_folder):
            os.makedirs(shared_folder)

        for file_path in file_paths:
            if not file_path:
                continue

            filename = os.path.basename(file_path)
            destination_path = os.path.join(shared_folder, filename)

            if os.path.abspath(file_path) == os.path.abspath(destination_path):
                messagebox.showerror("Error", "Source and destination paths are the same.")
                continue

            if os.path.exists(destination_path):
                # File already exists, ask for confirmation to overwrite
                if not messagebox.askyesno("File Exists", f"The file '{filename}' already exists. Do you want to overwrite it?"):
                    continue

            try:
                encrypted_data = self.encrypt_file(file_path)
                with open(destination_path, 'wb') as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Success", f"File '{filename}' uploaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload file '{filename}': {str(e)}")

        self.view_files()  # Refresh file list after upload

    def view_files(self):
        shared_folder = "shared"
        if os.path.exists(shared_folder):
            files = os.listdir(shared_folder)
            self.file_listbox.delete(0, tk.END)
            for file in files:
                self.file_listbox.insert(tk.END, file)

    def organize_files(self):
        pass  # Placeholder for organizing files (e.g., move files to folders)

    def delete_file(self):
        file_name = self.file_listbox.get(tk.ACTIVE)
        shared_folder = "shared"
        file_path = os.path.join(shared_folder, file_name)

        if not file_name:
            messagebox.showerror("Error", "Please select a file to delete.")
            return

        if messagebox.askyesno("Confirmation", f"Are you sure you want to delete '{file_name}'?"):
            try:
                os.remove(file_path)
                messagebox.showinfo("Success", "File deleted successfully.")
                self.view_files()  # Refresh file list after successful deletion
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()
