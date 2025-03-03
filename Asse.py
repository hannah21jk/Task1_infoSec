import hashlib
import string
import itertools
import sys
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk  

letters = string.ascii_letters  # all uppercase and lowercase letters in the alphabet

# Dictionary Attack
def dictionary_attack(hash_input, stop_flag):
    dic_list = []
    print("\nStarting Dictionary Attack...")
    try:
        with open("rookyou.txt", errors='ignore') as dictionary_file:
            contents = dictionary_file.readlines()
            for word in contents:
                new_word = word.replace("\n", "")
                dic_list.append(new_word)

        for password in dic_list:
            if stop_flag[0]:  # Check if stopped
                print("\nAttack stopped.")
                return None
            print(f"Trying password: {password}")
            if len(hash_input) == 32:
                dic_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
            elif len(hash_input) == 40:
                dic_hash = hashlib.sha1(password.encode("utf-8")).hexdigest()
            elif len(hash_input) == 64:
                dic_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

            # Check if hash matches
            if dic_hash == hash_input:
                print(f"\nPassword Found! {password}")
                return password  
    except FileNotFoundError:
        print("\nDictionary file 'rookyou.txt' not found!")
    return None 

# Brute Force Attack
def brute_force_attack(hash_input, stop_flag):
    print("\nStarting Brute Force Attack...")

    num_of_char = 5  

    possible_passwords = itertools.product(letters, repeat=num_of_char)

    try:
        for combo in possible_passwords:
            if stop_flag[0]:  # Check if stopped
                print("\nAttack stopped.")
                return None
            # Generate the string from the combination
            gen_str = ''.join(combo)
            print(f"Trying password: {gen_str}")

            if len(hash_input) == 32:
                generated_hash = hashlib.md5(gen_str.encode("utf-8")).hexdigest()
            elif len(hash_input) == 40:
                generated_hash = hashlib.sha1(gen_str.encode("utf-8")).hexdigest()
            elif len(hash_input) == 64:
                generated_hash = hashlib.sha256(gen_str.encode("utf-8")).hexdigest()

            if generated_hash == hash_input:
                print(f"\nPassword Found: {gen_str}")
                return gen_str  
    except KeyboardInterrupt:
        print("\nBrute force attack stopped by user.")
        sys.exit(0)  

    print("\nBrute Force Failed, no password matched.")
    return None  

# GUI 
def start_attack():
    hash_input = hash_entry.get().strip()
    username = username_entry.get().strip()
    attack_type = attack_var.get()

    if not hash_input:
        messagebox.showerror("Error", "Please enter a hash.")
        return

    stop_flag[0] = False  

    if attack_type == 1:  # Dictionary Attack
        result = dictionary_attack(hash_input, stop_flag)
    elif attack_type == 2:  # Brute Force Attack
        result = brute_force_attack(hash_input, stop_flag)
    else:
        messagebox.showerror("Error", "Please select an attack type.")
        return

    if result:
        messagebox.showinfo("Success", f"Password Found: {result}")
    else:
        messagebox.showinfo("Failure", "Password not found.")

# Stop the attack
def stop_attack():
    stop_flag[0] = True
    messagebox.showinfo("Stopped", "The attack has been stopped.")
stop_flag = [False] 

# window design
root = tk.Tk()
root.title("Password Cracker")
root.geometry("700x400")
root.config(bg="#343a40")

frame = tk.Frame(root, bg="#ffffff", bd=10, relief="solid", padx=20, pady=20)
frame.place(relwidth=0.9, relheight=0.8, relx=0.05, rely=0.1)

title_label = tk.Label(frame, text="Password Cracker", bg="#ffffff", fg="#212529", font=("Helvetica", 16, "bold"))
title_label.grid(row=0, column=0, columnspan=2, pady=20)

label_font = ("Helvetica", 12, "bold")
entry_font = ("Helvetica", 12)
button_font = ("Helvetica", 12, "bold")

tk.Label(frame, text="Enter Hash:", bg="#ffffff", fg="#495057", font=label_font).grid(row=1, column=0, padx=10, pady=10, sticky="e")
hash_entry = tk.Entry(frame, width=40, bg="#f8f9fa", fg="#212529", font=entry_font, bd=2, relief="solid")
hash_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(frame, text="Enter Username:", bg="#ffffff", fg="#495057", font=label_font).grid(row=2, column=0, padx=10, pady=10, sticky="e")
username_entry = tk.Entry(frame, width=40, bg="#f8f9fa", fg="#212529", font=entry_font, bd=2, relief="solid")
username_entry.grid(row=2, column=1, padx=10, pady=10)

attack_var = tk.IntVar()
radio_frame = tk.Frame(frame, bg="#ffffff")
radio_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="n")

style = ttk.Style()
style.configure("Modern.TRadiobutton",
                background="#ffffff",
                foreground="#495057",
                font=label_font,
                padding=5)

ttk.Radiobutton(radio_frame, text="Dictionary Attack", variable=attack_var, value=1, style="Modern.TRadiobutton").grid(row=0, column=0, padx=20, pady=10)
ttk.Radiobutton(radio_frame, text="Brute Force Attack", variable=attack_var, value=2, style="Modern.TRadiobutton").grid(row=0, column=1, padx=20, pady=10)


tk.Button(frame, text="Start Attack", command=start_attack, bg="#007bff", fg="#ffffff", font=button_font, relief="solid", bd=2, width=20).grid(row=4, column=0, columnspan=2, pady=5)

root.mainloop()
