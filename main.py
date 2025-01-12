import random
from typing import List
import re


upper_case_characters: List[str] = [chr(i) for i in range(65, 91)]  # A-Z
lower_case_characters: List[str] = [chr(i) for i in range(97, 123)]  # a-z
digits: List[str] = [chr(i) for i in range(48, 58)]  # 0-9
special_characters = [
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'
]

options = {
    "1": "Check password Strength",
    "2": "Create your own password",
    "3": "Get a machine-generated password"
}


def generate_password(length: int) -> str:
    all_characters = upper_case_characters + lower_case_characters + digits + special_characters
    if length >= 8:
        password = ''.join(random.choices(all_characters, k=length))
    else:
        password = ''.join(random.choices(upper_case_characters + lower_case_characters + digits, k=length))
    return password


def password_strength(password: str):
    score = 0
    # Length checks
    if len(password) >= 8:
        score += 2
    if len(password) >= 12:
        score += 2

    # Character type checks
    if re.search(r'[A-Z]', password):
        score += 2
    if re.search(r'[a-z]', password):
        score += 2
    if re.search(r'[0-9]', password):
        score += 2
    if re.search(r'[\W_]', password):
        score += 2

    # Determine strength
    if score <= 4:
        strength = "Weak"
        rating = "2/10"
    elif score <= 6:
        strength = "Average"
        rating = "5/10"
    elif score <= 8:
        strength = "Good"
        rating = "7/10"
    else:
        strength = "Strong"
        rating = "10/10"

    return strength, rating


def main():
    print("Welcome to the Password Generator and Strength Checking Tool!")
    user_name = input("Enter your name to start: ")
    print(f"Hi {user_name}! Here are our services:")
    for key, value in options.items():
        print(f"{key}: {value}")

    choice = input("Enter your service choice: ")

    try:
        if choice == "3":
            platform_name = input("Enter the name of platform for which you need the password : ")
            pass_length = int(input("Enter the length of the password (4/8/12/16): "))
            if pass_length not in [4, 8, 12, 16]:
                print("Invalid length. Please choose from 4, 8, 12, or 16.")
            else:
                generated_password = generate_password(pass_length)
                strength, rating = password_strength(generated_password)
                print(f"Your machine-generated password for {platform_name} account: {generated_password}")
                print(f"Password Strength: {strength}, Rating: {rating}")

        elif choice == "2":
            platform_name = input("Enter the name of platform for which you need the password : ")
            custom_pass = input("Create your custom password: ")
            if len(custom_pass.strip()) == 0:
                print("Password cannot be empty.")
            else:
                strength, rating = password_strength(custom_pass)
                print(f"Password created successfully for your {platform_name} account: {custom_pass}")
                print(f"Password Strength: {strength}, Rating: {rating}")

        elif choice == "1":
            test_password = input("Enter the password to check its strength: ")
            if len(test_password.strip()) == 0:
                print("Password cannot be empty.")
            else:
                strength, rating = password_strength(test_password)
                print(f"Password Strength: {strength}, Rating: {rating}")

        else:
            print("Wrong choice entered, Please try again!")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()