import bcrypt
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
import sys

class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}

    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()

    def create_password_files(self, path, initial_values=None):
        self.password_file = path

        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)

    def load_password_file(self, path, password):
        self.password_file = path
        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.split(":")
                decrypted = self._decrypt_password(encrypted.strip())
                self.password_dict[site] = decrypted.decode()

    def add_password(self, site, password, password_hash=None):
        if password_hash is None:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        self.password_dict[site] = password_hash
        if self.password_file is not None:
            with open(self.password_file, 'a') as f:
                encrypted = self._encrypt_password(password_hash)
                f.write(site + ":" + encrypted + "\n")

    def get_password(self, site, password):
        stored_password = self.password_dict.get(site)

        if stored_password:
            if bcrypt.checkpw(password.encode(), stored_password):
                return stored_password
            else:
                raise ValueError("Incorrect password")
        else:
            raise KeyError("Site not found in password dictionary")

    def _encrypt_password(self, password):
        return Fernet(self.key).encrypt(password)

    def _decrypt_password(self, encrypted):
        decrypted = Fernet(self.key).decrypt(encrypted)
        return decrypted


class PasswordManagerWindow(QWidget):
    def __init__(self, password_manager):
        super().__init__()
        self.password_manager = password_manager
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager")

        # Create widgets and layout
        label = QLabel("Enter password:")
        self.password_input = QLineEdit()
        submit_button = QPushButton("Submit")

        # Connect signals and slots
        submit_button.clicked.connect(self.submit_password)

        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addWidget(self.password_input)
        layout.addWidget(submit_button)

        # Set the layout for the window
        self.setLayout(layout)

    def submit_password(self):
        # Handle password submission
        password = self.password_input.text()

        # Add your logic here
        site = 'site1'  # Replace with the appropriate site value
        try:
            retrieved_password = self.password_manager.get_password(site, password)
            print(f"Retrieved password for {site}: {retrieved_password}")
        except ValueError as e:
            print(f"Error: {str(e)}")
        except KeyError as e:
            print(f"Error: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    password_manager = PasswordManager()
    key_file = 'key.key'
    password_file = 'passwords.txt'
    initial_passwords = {'site1': 'password1', 'site2': 'password2'}
    password = 'masterpassword'

    try:
        password_manager.create_key(key_file)
        password_manager.load_key(key_file)
        password_manager.create_password_files(password_file, initial_passwords)
        password_manager.load_password_file(password_file, password)

    except FileNotFoundError:
        print(f"File not found: {password_file}")
    except ValueError as e:
        print(f"Error: {str(e)}")
    except KeyError as e:
        print(f"Error: {str(e)}")

    window = PasswordManagerWindow(password_manager)
    window.show()
    sys.exit(app.exec_())


