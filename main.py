import binascii
from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def SaveFile ():
    title=entry_title.get()
    message= text_secret.get("1.0",END)
    master_secret=password_entry.get()
    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Bildiriş", message="Məlumatları girin")
    else:
        enscrypt_message= encode(master_secret,message)
        try:
            with open ("gizlidosya.txt","a") as data_file:
                data_file.write(f"\nGizli: {title}\n{enscrypt_message}\n")
                messagebox.showinfo(title="Bildiriş", message="Uğurla Yazıldı")

        except FileNotFoundError :
            with open ("gizlidosya.txt","w") as data_file:
                data_file.write(f"\nGizli: {title}\n{enscrypt_message}\n")
                messagebox.showinfo(title="Bildiriş", message="Uğurla Yazıldı")
        finally:
            text_secret.delete("1.0",END)
            entry_title.delete(0,END)
            password_entry.delete(0,END)

def decrypt_notes():
    message_encrypted = text_secret.get("1.0", END)
    master_secret = password_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            text_secret.delete("1.0", END)
            text_secret.insert("1.0", decrypted_message)
        except:
            messagebox.showerror(title="Xəta baş verdi", message="Şifrəli sözlü və ya şifrənizi düzgun daxil edin")


#Display   ----------------------------------------------
window= Tk()
window.title("Hasanzade")
window.config(padx=20,pady=20)
FONT=("Verdena",10,"bold")

photo=PhotoImage(file=r"C:\Users\Amil Hasanzade\AppData\Local\Programs\Python\Python311\enc1.png.png")
photo_label=Label(image=photo)
photo_label.pack()

title_label = Label(text="- Başliq Yaz -",font= FONT)
title_label.pack()

entry_title=Entry()
entry_title.config(width=30)
entry_title.pack()


secret_label = Label(text="- Gizli mesajınızı daxil edin -",font= FONT)
secret_label.config(padx=10,pady=10)
secret_label.pack()

text_secret=Text()
text_secret.config(width=30,height=10)
text_secret.pack()


key_label=Label(text="- Şifrənizi daxil edin -",font=FONT)
key_label.config(padx=10,pady=10)
key_label.pack()


password_entry=Entry()
password_entry.config(width=30)
password_entry.pack()

probel_label=Label(text="")
probel_label.pack()

save_button=Button(text="Yadda saxla ve Şifrələ",command=SaveFile)
save_button.pack()

descrypt_button=Button(text="Göster",command=decrypt_notes)
descrypt_button.pack()
window.mainloop()
