import random
import re
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox)

# Character Sets
upper_case_characters = [chr(i) for i in range(65, 91)]  # A-Z
lower_case_characters = [chr(i) for i in range(97, 123)]  # a-z
digits = [chr(i) for i in range(48, 58)]  # 0-9
special_characters = [
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'
]

def generate_password(length):
    all_characters = upper_case_characters + lower_case_characters + digits + special_characters
    if length >= 8:
        return ''.join(random.choices(all_characters, k=length))
    else:
        return ''.join(random.choices(upper_case_characters + lower_case_characters + digits, k=length))

def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 2
    if len(password) >= 12:
        score += 2
    if re.search(r'[A-Z]', password):
        score += 2
    if re.search(r'[a-z]', password):
        score += 2
    if re.search(r'[0-9]', password):
        score += 2
    if re.search(r'[\W_]', password):
        score += 2

    if score <= 4:
        return "Weak", "2/10"
    elif score <= 6:
        return "Average", "5/10"
    elif score <= 8:
        return "Good", "7/10"
    else:
        return "Strong", "10/10"

class PasswordManagerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 300)

        # Widgets
        self.platform_label = QLabel("Platform Name:")
        self.platform_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.length_label = QLabel("Password Length:")
        self.length_input = QComboBox()
        self.length_input.addItems(["4", "8", "12", "16"])

        self.result_label = QLabel("")

        self.check_button = QPushButton("Check Password Strength")
        self.check_button.clicked.connect(self.check_password_strength)

        self.custom_button = QPushButton("Create Custom Password")
        self.custom_button.clicked.connect(self.create_custom_password)

        self.generate_button = QPushButton("Generate Random Password")
        self.generate_button.clicked.connect(self.generate_random_password)

        # Layout
        layout = QVBoxLayout()

        platform_layout = QHBoxLayout()
        platform_layout.addWidget(self.platform_label)
        platform_layout.addWidget(self.platform_input)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)

        length_layout = QHBoxLayout()
        length_layout.addWidget(self.length_label)
        length_layout.addWidget(self.length_input)

        layout.addLayout(platform_layout)
        layout.addLayout(password_layout)
        layout.addLayout(length_layout)
        layout.addWidget(self.check_button)
        layout.addWidget(self.custom_button)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def check_password_strength(self):
        password = self.password_input.text()
        if not password.strip():
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        strength, rating = password_strength(password)
        self.result_label.setText(f"Strength: {strength}, Rating: {rating}")

    def create_custom_password(self):
        platform = self.platform_input.text()
        password = self.password_input.text()
        if not password.strip():
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        strength, rating = password_strength(password)
        self.result_label.setText(f"Password for {platform}: {password}\nStrength: {strength}, Rating: {rating}")

    def generate_random_password(self):
        platform = self.platform_input.text()
        try:
            length = int(self.length_input.currentText())
            password = generate_password(length)
            strength, rating = password_strength(password)
            self.result_label.setText(f"Generated Password for {platform}: {password}\nStrength: {strength}, Rating: {rating}")
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid number for length.")

if __name__ == "__main__":
    app = QApplication([])
    window = PasswordManagerApp()
    window.show()
    app.exec_()
