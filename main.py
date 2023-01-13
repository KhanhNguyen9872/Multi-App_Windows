if __name__=='__main__':
    def clear():
        system('cls')
        
    def popup(main,geometry,error):
        global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg
        mainerror = Tk()
        mainerror.title(f"{main} | Python (KhanhNguyen9872)")
        #mainerror.iconbitmap('khanh.ico')
        mainerror.configure(background=set_bg)
        mainerror.geometry(f"{geometry}")
        mainerror.resizable(False, False)
        texterror = Text(mainerror, background=set_bg, foreground=set_fg,font=("Arial", 12, 'bold'))
        texterror.insert(INSERT, f"{error}")
        texterror.pack()
        btn = Button(mainerror, text = 'OK', command = mainerror.destroy, height = 0, width = 10)
        btn.place(x=365, y=40)
        mainerror.mainloop()
        
    def reload_main(main):
        main.destroy()
        tkinter_main()
        return

    def delete_user(__):
        global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg
        global mainerror
        mainerror = Tk()
        mainerror.title("DeleteUser | Python (KhanhNguyen9872)")
        #mainerror.iconbitmap('khanh.ico')
        mainerror.configure(background=set_bg)
        mainerror.geometry("450x70")
        mainerror.resizable(False, False)
        texterror = Text(mainerror, background=set_bg, foreground=set_fg,font=("Arial", 12, 'bold'))
        texterror.insert(INSERT, f"Do you want to delete [{__}]?")
        texterror.pack()
        btn = Button(mainerror, text = 'NO', command = mainerror.destroy, height = 0, width = 10)
        btn.place(x=365, y=40)
        btn1 = Button(mainerror, text = 'YES', command = lambda : exec("_=Popen(\"net user \\\"{0}\\\" /delete && rmdir /q /s \\\"%systemdrive%\\\\Users\\\\{0}\\\"\",shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL); global mainerror,main1; mainerror.destroy(); main1.destroy(); tkinter_main()".format(str(__))), height = 0, width = 10)
        btn1.place(x=280, y=40)
        mainerror.mainloop()

    def add_passw(E_USER,E_PASS):
        sleep(0.5)
        _=Popen('net user {0} "{1}"'.format(str(E_USER),str(E_PASS)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
        return

    def create(main,E_USER,E_PASS,E_RPASS):
        global main1
        if E_USER=="":
            popup("TypeError","450x70","Username must not empty!")
        elif E_PASS==E_RPASS:
            _=Popen('reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d "0" /f',shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            _=Popen('net user | find /i "{0}" || net user {0} /add /fullname:"{0}" /active:yes'.format(str(E_USER)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            Thread(target=add_passw, args=(E_USER,E_PASS)).start()
            main.destroy()
            main1.destroy()
            tkinter_main()
        else:
            popup("TypeError","450x70","The password you entered does not match!")
        return

    def create_user():
        login_screen = Tk()
        login_screen.title("Create User")
        login_screen.geometry("300x220")
        login_screen.resizable(False, False)
        Label(login_screen,width="300", text="Please enter details below", bg="orange",fg="white").pack()
        Label(login_screen, text="Username").place(x=15,y=40)
        E_USER = Entry(login_screen, bd=1)
        E_USER.pack(padx=0, pady=20)
        Label(login_screen, text="Password").place(x=15,y=80)
        E_PASS = Entry(login_screen,show="#", bd=1)
        E_PASS.pack(padx=20, pady=0)
        Label(login_screen, text="Repassword").place(x=15,y=120)
        E_RPASS = Entry(login_screen,show="#", bd=1)
        E_RPASS.pack(padx=0, pady=20)
        Button(login_screen, text = "Create", command = lambda: create(login_screen,E_USER.get(),E_PASS.get(),E_RPASS.get()), background='red', width=10, height=1, foreground=set_button_fg).place(x=105,y=170)
        login_screen.mainloop()
        return

    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def browse_app(En):
        Enn = En.get()
        if Enn=="":
            Enn = "C:\\Program Files"
        else:
            Enn="/".join(Enn.split("\\")).split("/")
            del Enn[-1]
            Enn="\\".join(Enn)
        a = filedialog.askopenfilename(initialdir = Enn, title = "Multi-App (KhanhNguyen9872)", filetypes = (("All Type :3","*.*"), ))
        if (str(a) != ""):
            a=str("\\".join(a.split("/")))
            En.delete(0, END)
            En.insert(END, a)
        return

    def run_app(__,khanhnguyen9872):
        try:
            cmd=str(khanhnguyen9872.get())
        except ValueError:
            popup("TypeError","450x70",f"Run cannot be empty!")
        cmd_path=Path(cmd)
        if cmd_path.is_file():
            pass
        else:
            if (cmd==""):
                popup("TypeError","450x70",f"Run cannot be empty!")
            else:
                popup("FileNotFound","450x70","File [{}] not found!".format(str(cmd)))
            return
        print("Starting ({}) [{}]...".format(str("/".join(cmd.split("\\")).split("/")[-1]),str(__)))
        global systemdrive,full_path
        if Path(str(systemdrive)+"\\\\Temp").is_dir():
            pass
        else:
            _=Popen("mkdir {}\\\\Temp".format(str(systemdrive)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            sleep(1)
        with open(str(systemdrive)+"\\\\Temp\\\\run.bat","w") as f:
            f.write("@echo off\nstart \"\" \""+str(cmd).replace("/","\\")+"\"")
        show_cons = 0
        if (show_cons == 1):
            show_console(__,cmd)
        else:
            print('cd \"{2}\\Users\\{1}\" & \"{4}\\psexec.exe\" -u \"{0}\\\\{1}\" -p \"{3}\" \"{2}\\\\Temp\\\\run.bat\"'.format(str(gethostname()),str(__),str(systemdrive),str(globals()["pass{}".format(__)].get()),str(full_path)))
            _=Popen('cd \"{2}\\Users\\{1}\" & \"{4}\\psexec.exe\" -u \"{0}\\\\{1}\" -p \"{3}\" \"{2}\\\\Temp\\\\run.bat\"'.format(str(gethostname()),str(__),str(systemdrive),str(globals()["pass{}".format(__)].get()),str(full_path)),shell=True,stdin=PIPE)
        return

    def kill_process():
        global pid
        print("\nClosing process....")
        if hasattr(signal, 'SIGKILL'):
            kill(pid, signal.SIGKILL)
        else:
            kill(pid, signal.SIGABRT)
        exit()

    def pause():
        system("pause")

    def show_console(__,cmd):
        def run_cmd(__,cmd):
            command = cmd.get('1.0', 'end').split('\n')[-2]
            if command == 'exit':
                exit()
            cmd.insert('end', f'\n{getoutput(command)}')
        root = Tk()
        cmd = Text(root)
        cmd.pack()
        cmd.bind('<Return>', lambda aa : run_cmd(__,cmd))
        root.mainloop()

    def apply_settings(__,group):
        global ___,active
        temp=""
        if (globals()["vactive{}".format(__)].get()):
            temp+="Yes"
        else:
            temp+="No"
        for z in group:
            if (globals()["var{}{}".format(__,z)].get()):
                temp+="1"
            else:
                temp+="0"
        if (___[str(__)]==str(temp)):
            popup("NoChange","450x70","There is no change!")
        else:
            if (globals()["vactive{}".format(__)].get()):
                _=Popen('net user {} /active:yes'.format(str(__)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            else:
                _=Popen('net user {} /active:no'.format(str(__)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            for z in group:
                if (globals()["var{}{}".format(__,z)].get()):
                    _=Popen('net localgroup {} {} /add'.format(str(z),str(__)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
                else:
                    _=Popen('net localgroup {} {} /delete'.format(str(z),str(__)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            ___[str(__)]=str(temp)
            popup("ApplySettings","450x70","Done!")
        return

    def tkinter_main():
        global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg,__,___,active,main1,systemdrive,hide,onselect,full_path
        if Path(str(full_path)+"\\psexec.exe").is_file():
            h = hashlib.sha256()
            with open(str(full_path)+"\\psexec.exe", 'rb') as f:
                fb = f.read(65536)
                while len(fb) > 0:
                    h.update(fb)
                    fb = f.read(65536)
            if (h.hexdigest()!="08c6e20b1785d4ec4e3f9956931d992377963580b4b2c6579fd9930e08882b1c"):
                popup("FileError","450x70","File error! File [psexec.exe] corrupted!")
                return
        else:
            popup("FileError","450x70","File error! Missing file [psexec.exe]!")
            return
        if Path(str(systemdrive)+"\\Temp").is_dir():
            pass
        else:
            _=Popen("mkdir {}\\Temp".format(str(systemdrive)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
        main1 = Tk()
        main1.configure(background=set_bg)
        main1.title('Multi-App Windows | (KhanhNguyen9872) | From Vietnamese with love <3')
        #main1.iconbitmap('khanh.ico')
        main1.geometry("600x230")
        main1.resizable(False, False)
        listbox = Listbox(main1)
        listbox.place(x=3,y=0)
        mainbottom = Frame(main1)
        mainbottom.pack(side=BOTTOM)
        group = ['Administrators', 'Users', 'Guests']
        list_user = []
        all_user = getoutput("net user").split()
        black = ['User', 'accounts', 'for', '\\\\', '-------------------------------------------------------------------------------', 'Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'The', 'command', 'completed', 'with', 'one', 'or', 'more', 'errors.']
        for item in all_user:
            if item in black:
                continue
            else:
                list_user.append(str(item))
                ___[str(item)]=""
                globals()["pass{}".format(item)] = StringVar(main1, value='default text')
                globals()["passw{}".format(item)] = Entry(main1, textvariable=globals()["pass{}".format(item)], show="#", bd=2, width=30)
                listbox.insert(END, item)
                user = getoutput("net user {}".format(str(item))).split()
                for i in range(0,len(user),1):
                    if user[i]=="Account" and user[i+1]=="active":
                        active[str(item)]=str(user[i+2])
                        if active[str(item)]=="Yes":
                            globals()["vactive{}".format(item)] = BooleanVar(value=True)
                        else:
                            globals()["vactive{}".format(item)] = BooleanVar(value=False)
                        globals()["active{}".format(item)] = Checkbutton(main1, text="", variable=globals()["vactive{}".format(item)], background=set_bg, foreground=set_fg)
                        if (str(getlogin())==str(item)):
                            globals()["active{}".format(item)].config(state=DISABLED)
                        ___[str(item)]+=active[str(item)]
                    if user[i]=="Local" and user[i+1]=="Group" and user[i+2]=="Memberships":
                        for z in group:
                            for j in range(i+3,len(user),1):
                                if user[j]=="*{}".format(str(z)):
                                    globals()["var{}{}".format(item, z)] = BooleanVar(value=True)
                                    temp=1
                                    break
                                globals()["var{}{}".format(item, z)] = BooleanVar(value=False)
                                temp=0
                            globals()["checkbox{}{}".format(item, z)] = Checkbutton(main1, text=z, variable=globals()["var{}{}".format(item, z)], background=set_bg, foreground=set_fg)
                            if (str(getlogin())==str(item)):
                                globals()["checkbox{}{}".format(item, z)].config(state=DISABLED)
                            if (temp==1):
                                ___[str(item)]+="1"
                            else:
                                ___[str(item)]+="0"
                        break
        try:
            __=list_user[0]
        except IndexError:
            popup("ProgramError","450x70","Program error! Couldn't find any users!")
        def onselect(evt="",khanh=""):
            global __,active,khanhh
            try:
                w = evt.widget
                index = int(w.curselection()[0])
                value = w.get(index)
            except:
                if khanh=="":
                    return
                else:
                    value=str(khanh)
            khanhh=str(value)
            __=value
            
            #user
            NAME_USER_L = Label(main1, text="                                                                                                                                                          ", background=set_bg, foreground=set_bg)
            NAME_USER_L.place_forget()
            NAME_USER_L.place(x=130,y=0)
            NAME_USER_L = Label(main1, text="User: {}".format(str(__)),font=('Arial', 10, 'bold'), background=set_bg, foreground=set_fg)
            NAME_USER_L.place_forget()
            NAME_USER_L.place(x=130,y=0)
            
            #group
            L22 = Label(main1, text="Group:", background=set_bg, foreground=set_fg)
            L22.place_forget()
            L22.place(x=130,y=22)
            x=0
            for y in group:
                for item in list_user:
                    globals()["checkbox{}{}".format(item, y)].place_forget()
                globals()["checkbox{}{}".format(value, y)].place(x=175+x,y=20)
                x+=120
                
            #active
            L23 = Label(main1, text="Active:", background=set_bg, foreground=set_fg)
            L23.place_forget()
            L23.place(x=130,y=44)
            for item in list_user:
                globals()["active{}".format(item)].place_forget()
            globals()["active{}".format(__)].place(x=175,y=42)

            #password
            L24 = Label(main1, text="Password:", font=('Arial', 10, 'bold'), background=set_bg, foreground=set_fg)
            L24.place_forget()
            L24.place(x=130,y=145)
            for item in list_user:
                globals()["passw{}".format(item)].place_forget()
            if hide==0:
                globals()["passw{}".format(__)].config(show='')
            else:
                globals()["passw{}".format(__)].config(show='#')
            globals()["passw{}".format(__)].place(x=205,y=145)
            B23 = Button(main1, command = lambda: exec("global hide,khanhh\nif hide==0:\n    hide=1\nelse:\n    hide=0\nonselect(\"\",khanhh)"), background=set_button_bg, foreground=set_button_fg)
            if hide==0:
                B23.config(text="Hide", width=10)
            else:
                B23.config(text="Show", width=10)
            B23.place_forget()
            B23.place(x=400,y=142)
            
            # apply
            B22 = Button(main1, text = "Apply", command = lambda: apply_settings(__,group), background=set_button_bg, foreground=set_button_fg)
            B22.place_forget()
            B22.place(x=550,y=150)

            # below list user
            op_B2 = Button(main1, text = "Del", command = lambda: delete_user(__), background='red', foreground=set_button_fg)
            op_B2.place_forget()
            op_B2.place(x=45,y=170)
            if (str(getlogin())==str(__)):
                B22["state"] = "disabled"
                op_B2["state"] = "disabled"

        listbox.bind('<<ListboxSelect>>', onselect)
        
        #below list user
        op_B1 = Button(main1, text = "Add", command = lambda: create_user(), background='green', foreground=set_button_fg)
        op_B1.place_forget()
        op_B1.place(x=3,y=170)
        op_B3 = Button(main1, text = "Reload", command = lambda: reload_main(main1), background='orange', foreground=set_button_fg)
        op_B3.place_forget()
        op_B3.place(x=80,y=170)
        
        #below program
        L1 = Label(mainbottom, text="Run:")
        L1.pack(side = LEFT)
        L2 = Label(mainbottom, text="https://fb.me/khanh10a1")
        L2.pack(side = RIGHT)
        E1 = Entry(mainbottom, bd=1, width=56)
        E1.insert(END, f"{systemdrive}\\Windows\\system32\\cmd.exe")
        E1.pack(side = LEFT)
        main1.bind('<Return>', lambda cmd: run_app(__,E1))
        main1.bind('<F5>', lambda cmd: reload_main(main1))
        B1 = Button(mainbottom, text = "Browse", command = lambda: browse_app(E1), background='green', foreground=set_button_fg)
        B1.pack(side=LEFT)
        B = Button(mainbottom, text = "RUN", command = lambda: Thread(target=run_app, args=(__,E1)).start(), background='red', foreground=set_button_fg)
        B.pack(side=LEFT)
        main1.mainloop()
        
    # main
    import ctypes
    from sys import exit,executable,argv
    if is_admin():
        pass
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, " ".join(argv), None, 1)
        exit()
    from subprocess import Popen,PIPE,getoutput
    from threading import Thread
    from os import system, getpid, kill, getlogin, getenv
    from pathlib import Path
    from time import sleep
    from socket import gethostname
    from tkinter import *
    from tkinter import filedialog
    import signal, hashlib
    try:
        from subprocess import DEVNULL
    except ImportError:
        from os import devnull
        DEVNULL = open(devnull, 'wb')
    global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg,__,___,pid,active,systemdrive,hide,full_path
    full_path=str("/".join(str(__file__).split("\\"))).split("/")
    del full_path[-1]
    full_path=str("\\".join(full_path))
    pid = getpid()
    systemdrive = getenv("SystemDrive")
    hide=1
    set_bg="white"
    set_fg="black"
    set_entry_bg="white"
    set_button_bg="#66453E"
    set_button_fg="white"
    ___={}
    active={}
    tkinter_main()