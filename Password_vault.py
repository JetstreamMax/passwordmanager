import sqlite3, hashlib 
from tkinter import *
from tkinter import simpledialog
from functools import partial

#Database
with sqlite3.connect('password_vault.db') as db:
  cursor = db.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
''')


cursor.execute('''
CREATE TABLE IF NOT EXISTS vault_table(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
''')

#Create Popup
def popUp(text):
  answer = simpledialog.askstring('input string', text)
  
  return answer

#Initial Window
window = Tk()

window.title('Password Vault')

def hashpassword(input):
  hash = hashlib.sha256(input)
  hash = hash.hexdigest()

  return hash

def initalscreen():
  window.geometry('350x150')

  lbl = Label(window, text = 'Create Master Password')
  lbl.config(anchor=CENTER)
  lbl.pack()

  txt = Entry(window, width=20, show='*')
  txt.pack()
  txt.focus()

  lbl1 = Label(window, text='Re-enter Password')
  lbl1.pack()

  txt1 = Entry(window, width=20, show='*')
  txt1.pack()
  txt1.focus()

  lbl2 = Label(window)
  lbl2.pack()


  def savepassword():
    if txt.get() == txt1.get():
      hashedpassword = hashpassword(txt.get().encode('utf-8'))
      insert_password = '''INSERT INTO masterpassword(password)
      VALUES(?) '''
      cursor.execute(insert_password, [(hashedpassword)])
      db.commit()

      passwordvault()
    else:
      lbl2.config(text='Passwords Do Not Match')


  btn = Button(window, text = 'Save', command=savepassword)
  btn.pack()


def loginscreen():
  window.geometry('350x150')

  lbl = Label(window, text = 'Enter Master Password')
  lbl.config(anchor=CENTER)
  lbl.pack()

  txt = Entry(window, width=20, show='*')
  txt.pack()
  txt.focus()

  lbl1 = Label(window)
  lbl1.pack()

  def getmasterpassword():
    checkhashedpassword = hashpassword(txt.get().encode('utf-8'))
    cursor.execute('SELECT * FROM masterpassword where id = 1 AND password = ?', [(checkhashedpassword)])
    print(checkhashedpassword)
    return cursor.fetchall()

  def checkpassword():
    match = getmasterpassword()

    print(match)

    if match:
      passwordvault()
    else:
      txt.delete(0, 'end')
      lbl1.config(text='Wrong Password')


  btn = Button(window, text = 'Submit', command=checkpassword)
  btn.pack()



#function to clear text on login screen
def passwordvault():
  for widget in window.winfo_children():
    widget.destroy()

  def addEntry():
    text1 = "WEBSITE"
    text2 = "USERNAME"
    text3 = "PASSWORD"

    website = popUp(text1)
    username = popUp(text2)
    password = popUp(text3)

    insert_fields = """INSERT INTO vault_table (website, username, password) VALUES(?, ?, ?)"""

    cursor.execute(insert_fields, (website, username, password))
    db.commit()

    passwordvault()

  def removeEntry(input):
    cursor.execute("DELETE FROM vault_table WHERE id = ?", (input,))
    db.commit()

    passwordvault()  

  window.geometry('700x350')

  lbl = Label(window, text = 'Password Vault')
  lbl.grid(column=1)

  btn = Button(window, text='+', command=addEntry)
  btn.grid(column=1, pady=10)

  lbl = Label(window, text='Website')
  lbl.grid(row=2, column=0, padx=80)
  lbl = Label(window, text='Username')
  lbl.grid(row=2, column=1, padx=80)
  lbl = Label(window, text='Password')
  lbl.grid(row=2, column=2, padx=80)

  cursor.execute('SELECT * FROM vault_table')
  if(cursor.fetchall() != None):
    i = 0
    while True:
      cursor.execute('SELECT * FROM vault_table')
      array = cursor.fetchall()

      lbl1 = Label(window, text=(array[i][1]), font=('Helvetica', 12))
      lbl1.grid(column=0, row=i+3)
      lbl1 = Label(window, text=(array[i][2]), font=('Helvetica', 12))
      lbl1.grid(column=1, row=i+3)
      lbl1 = Label(window, text=(array[i][3]), font=('Helvetica', 12))
      lbl1.grid(column=2, row=i+3)

      btn = Button(window, text='Delete', command=partial(removeEntry, array[i][0]))
      btn.grid(column=3, row=i+3, pady=10)

      i = i+1

      cursor.execute('SELECT * FROM vault_table')
      if (len(cursor.fetchall()) <= i):
        break


cursor.execute('SELECT * FROM masterpassword')
if cursor.fetchall():
  loginscreen()
else:
  initalscreen()
window.mainloop()

