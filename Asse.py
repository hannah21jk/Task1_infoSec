import hashlib
import string
import itertools
import sys
import tkinter as tk
from tkinter import messagebox

letters = string.ascii_letters  # all uppercase and lowercase letters in the alphabet

# Dictionary Attack
def dictionary_attack(hash_input):
    dic_list = []
    print("\nStarting Dictionary Attack...")
    try:
        with open("rookyou.txt", errors='ignore') as dictionary_file:
            contents = dictionary_file.readlines()
            for word in contents:
                new_word = word.replace("\n", "")
                dic_list.append(new_word)

        for password in dic_list:
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
def brute_force_attack(hash_input):
    print("\nStarting Brute Force Attack...")

    num_of_char = 5  

    possible_passwords = itertools.product(letters, repeat=num_of_char)

    try:
        for combo in possible_passwords:
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
                return gen_str  # Found the password
    except KeyboardInterrupt:
        print("\nBrute force attack stopped by user.")
        sys.exit(0)  

    print("\nBrute Force Failed, no password matched.")
    return None  # If password is not found

# GUI 
def start_attack():
    hash_input = hash_entry.get().strip()
    username = username_entry.get().strip()
    attack_type = attack_var.get()

    if not hash_input:
        messagebox.showerror("Error", "Please enter a hash.")
        return

    if attack_type == 1:  # Dictionary Attack
        result = dictionary_attack(hash_input)
    elif attack_type == 2:  # Brute Force Attack
        result = brute_force_attack(hash_input)
    else:
        messagebox.showerror("Error", "Please select an attack type.")
        return

    if result:
        messagebox.showinfo("Success", f"Password Found: {result}")
    else:
        messagebox.showinfo("Failure", "Password not found.")

root = tk.Tk()
root.title("Password Cracker")
root.geometry("600x300")

frame = tk.Frame(root, bg="#14213d" )
frame.place(relwidth=1, relheight=1, relx=0.001, rely=0.001)

# Create and place widgets with custom colors and fonts
label_font = ("Helvetica", 12, "bold")
entry_font = ("Helvetica", 12, "bold")
button_font = ("Helvetica", 12, "bold")

tk.Label(frame, text="Enter Hash:", bg="#14213d", fg="#c1121f", font=label_font).grid(row=0, column=0, padx=10, pady=10, sticky="e")
hash_entry = tk.Entry(frame, width=40, bg="#e7ecef", fg="#c1121f", font=entry_font)
hash_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(frame, text="Enter Username:", bg="#14213d", fg="#c1121f", font=label_font).grid(row=1, column=0, padx=10, pady=10, sticky="e")
username_entry = tk.Entry(frame, width=40, bg="#e7ecef", fg="#c1121f", font=entry_font)
username_entry.grid(row=1, column=1)

attack_var = tk.IntVar()
tk.Radiobutton(frame, text="Dictionary Attack", variable=attack_var, value=1, bg="#14213d", fg="#c1121f", selectcolor="#e7ecef", font=label_font ).grid(row=2, column=0, padx=10, pady=10, sticky="w")
tk.Radiobutton(frame, text="Brute Force Attack", variable=attack_var, value=2, bg="#14213d", fg="#c1121f", selectcolor="#e7ecef", font=label_font).grid(row=2, column=1, padx=10, pady=10, sticky="w")

tk.Button(frame, text="Start Attack", command=start_attack, bg="#e7ecef", fg="#c1121f", font=button_font).grid(row=3, column=0, columnspan=2, pady=20)

root.mainloop()