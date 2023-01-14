if __name__=='__main__':
    from os import name
    if (name=="nt"):
        def popup(main,error,type_pop=1,exec_pop=""):
            global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg,mainerror
            mainerror = Tk()
            mainerror.title("{} | Python (KhanhNguyen9872)".format(str(main)))
            #mainerror.iconbitmap('khanh.ico')
            mainerror.configure(background=set_bg)
            mainerror.geometry(center_screen(450,70,mainerror))
            mainerror.resizable(False, False)
            texterror = Text(mainerror, background=set_bg, foreground=set_fg,font=("Arial", 10, 'bold'))
            texterror.insert(INSERT, str(error))
            texterror.pack()
            btn = Button(mainerror, text = 'OK', command = mainerror.destroy, height = 0, width = 10)
            btn.place(x=365, y=40)
            if type_pop==2:
                btn.config(text = "NO")
                btn1 = Button(mainerror, text = 'YES', command = lambda : exec(str(exec_pop)), height = 0, width = 10)
                btn1.place(x=280, y=40)
            mainerror.protocol("WM_DELETE_WINDOW", mainerror.destroy)
            mainerror.mainloop()
            
        def reload_main(main):
            main.destroy()
            tkinter_main()
            return

        def add_passw(E_USER,E_PASS):
            sleep(0.5)
            _=Popen('net user {0} "{1}"'.format(str(E_USER),str(E_PASS)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
            return

        def create(main,E_USER,E_PASS,E_RPASS):
            global main1,list_user
            if E_USER=="":
                popup("TypeError","Username must not empty!")
            elif E_USER in list_user:
                popup("UserExists","Username [{}] already exists!".format(str(E_USER)))
            elif E_PASS==E_RPASS:
                _=Popen('reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d "0" /f',shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
                _=Popen('net user | find /i "{0}" || net user {0} /add /fullname:"{0}" /active:yes'.format(str(E_USER)),shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL)
                Thread(target=add_passw, args=(E_USER,E_PASS)).start()
                main.destroy()
                main1.destroy()
                tkinter_main()
            else:
                popup("TypeError","The password you entered does not match!")
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
            login_screen.bind('<Return>', lambda cmd: create(login_screen,E_USER.get(),E_PASS.get(),E_RPASS.get()))
            login_screen.protocol("WM_DELETE_WINDOW", login_screen.destroy)
            login_screen.mainloop()
            return

        def is_admin():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False

        def check_sha256(file):
            h = hashlib.sha256()
            with open(file, 'rb') as f:
                fb = f.read(65536)
                while len(fb) > 0:
                    h.update(fb)
                    fb = f.read(65536)
            return h

        def browse_app(En):
            global allow_program
            exee=""
            for exe in allow_program:
                exee+="*.{} ".format(str(exe))
            Enn = En.get()
            if Enn=="":
                Enn = "C:\\Program Files"
            else:
                Enn="/".join(Enn.split("\\")).split("/")
                del Enn[-1]
                Enn="\\".join(Enn)
            a = filedialog.askopenfilename(initialdir = Enn, title = "Multi-App (KhanhNguyen9872)", filetypes = [("Application Type :3",exee)])
            if (str(a) != ""):
                a=str("\\".join(a.split("/")))
                En.delete(0, END)
                En.insert(END, a)
            return

        def run_app(__,khanhnguyen9872):
            if __=="":
                popup("NoUser",f"Please choose one user before Run!")
                return
            try:
                cmd=str(khanhnguyen9872.get())
            except ValueError:
                popup("TypeError",f"Run cannot be empty!")
                return
            cmd_path=Path(cmd)
            if (cmd==""):
                popup("TypeError",f"Run cannot be empty!")
                return
            elif cmd_path.is_file():
                pass
            elif cmd_path.is_dir():
                popup("NotAFile","File required! Not a folder [{}]!".format(str(cmd)))
                return
            else:
                popup("FileNotFound","File [{}] not found!".format(str(cmd)))
                return
            nameprogram=str("/".join(cmd.split("\\")).split("/")[-1])
            global allow_program
            type_exec = str(nameprogram.split(".")[-1])
            if type_exec in allow_program:
                pass
            else:
                popup("TypeFileError","File [{}] not allowed!".format(nameprogram))
                return
            global systemdrive,full_path
            if Path(str(systemdrive)+"\\\\Temp").is_dir():
                pass
            else:
                mkdir("{0}\\Temp".format(str(systemdrive)))
                sleep(0.25)
            cmd = str(path.realpath(cmd))
            rand = str(random_str())
            with open(str(systemdrive)+"\\\\Temp\\\\{}.bat".format(str(rand)),"w") as f:
                f.write("@echo off\n")
                if type_exec == "exe" and nameprogram != "cmd.exe":
                    cmd_path = str(cmd).replace("/","\\").split("\\")
                    del cmd_path[-1]
                    cmd_path = str("\\".join(cmd_path))
                    f.write("cd \"{0}\" >NUL 2>&1\n".format(str(cmd_path)))
                else:
                    f.write("cd \"{0}\\Users\\{1}\" >NUL 2>&1\n".format(str(systemdrive),str(__)))
                f.write("start \"{0} [{1}] | KhanhNguyen9872\" \"{2}\"".format(str(nameprogram),str(__),str(cmd).replace("/","\\")))
            # show_cons = 0
            # if (show_cons == 1):
            #     show_console(__,cmd)
            # else:
            _=check_psexec()
            if _==1:
                return
            print("Starting ({}) [{}]...".format(str(nameprogram),str(__)))
            temp1 = getoutput('\"{4}\\psexec.exe\" -u \"{0}\\\\{1}\" -p \"{3}\" \"{2}\\\\Temp\\\\{5}.bat\"'.format(str(gethostname()),str(__),str(systemdrive),str(globals()["pass{}".format(__)].get()),str(full_path),str(rand))).split()
            if (str(temp1[-7]+" "+temp1[-6]+" "+temp1[-5]+" "+temp1[-4]+" "+temp1[-3]+" "+temp1[-2]+" "+temp1[-1]) == "The user name or password is incorrect."):
                popup("PasswordError","Password error! If your User doesn't have a password, leave it blank!")
            elif (str(temp1[-3]+" "+temp1[-2]) == "error code") and (str(temp1[-1]) != "0."):
                popup("ProgramExitCode","[{}] return error code {}".format(str(nameprogram),str(temp1[-1])))
            elif (str(temp1[-5]+" "+temp1[-4]+" "+temp1[-3]+" "+temp1[-2]+" "+temp1[-1]) == "policy restriction has been enforced."):
                popup("UserDisabled","User [{}] has been disabled".format(str(__)))
            elif (str(temp1[-7]+" "+temp1[-6]+" "+temp1[-5]+" "+temp1[-4]+" "+temp1[-3]+" "+temp1[-2]+" "+temp1[-1]) == "the requested logon type at this computer."):
                popup("PermissionDenied","User [{}] has not been granted the requested logon type at this computer.".format(str(__)))
            remove("{0}\\\\Temp\\\\{1}.bat".format(str(systemdrive),str(rand)))
            return

        def center_screen(w,h,____):
            ws = ____.winfo_screenwidth()
            hs = ____.winfo_screenheight()
            x = (ws/2) - (w/2)
            y = (hs/2) - (h/2)
            return '%dx%d+%d+%d' % (w, h, x, y)

        def random_str(length=12):
            return "".join([choice('qwertyuiopasdfghjklzxcvbnm1234567890') for _ in range(length)])

        def kill_process():
            global pid
            print("\nClosing process....")
            if hasattr(signal, 'SIGKILL'):
                kill(pid, signal.SIGKILL)
            else:
                kill(pid, signal.SIGABRT)
            exit()

        # def show_console(__,cmd):
        #     def run_cmd(__,cmd):
        #         command = cmd.get('1.0', 'end').split('\n')[-2]
        #         if command == 'exit':
        #             exit()
        #         cmd.insert('end', f'\n{getoutput(command)}')
        #     root = Tk()
        #     cmd = Text(root)
        #     cmd.pack()
        #     cmd.bind('<Return>', lambda aa : run_cmd(__,cmd))
        #     root.mainloop()

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
                popup("NoChange","There is no change!")
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
                popup("ApplySettings","Apply [{}] Done!".format(str(__)))
            return

        def check_psexec():
            global full_path
            file_required = [
            "psexec.exe",
            ]
            sha256_file = [
            "08c6e20b1785d4ec4e3f9956931d992377963580b4b2c6579fd9930e08882b1c",
            ]
            for file in range(0,len(file_required),1):
                if Path(str(full_path)+"\\{}".format(str(file_required[file]))).is_file():
                    h = check_sha256(str(full_path)+"\\{}".format(str(file_required[file])))
                    if (h.hexdigest()!=sha256_file[file]):
                        popup("FileError","File error! File [{}] corrupted!".format(str(file_required[file])))
                        return 1
                else:
                    popup("FileError","File error! Missing file [{}]!".format(str(file_required[file])))
                    return 1
            return 0

        def tkinter_main():
            global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg,__,___,active,main1,systemdrive,hide,onselect,full_path,temp2,list_user
            temp2=0
            _=check_psexec()
            if _==1:
                return
            if Path(str(systemdrive)+"\\Temp").is_dir():
                pass
            else:
                mkdir("{0}\\Temp".format(str(systemdrive)))
            main1 = Tk()
            main1.configure(background=set_bg)
            main1.title('Multi-App Windows | (KhanhNguyen9872) | From Vietnamese with love <3')
            #main1.iconbitmap('khanh.ico')
            main1.geometry(center_screen(605,230,main1))
            main1.resizable(False, False)
            listbox = Listbox(main1)
            listbox.place(x=3,y=0)
            mainbottom = Frame(main1)
            mainbottom.pack(side=BOTTOM)
            group = ['Administrators', 'Users', 'Guests']
            list_user = []
            all_user = getoutput("net user").split()
            system_user = ["Administrator", "DefaultAccount", "WDAGUtilityAccount"]
            for item in all_user:
                if (system("net user \"{0}\" 2>NULL | find /I \"{0}\" >NUL".format(str(item))) == 1):
                    continue
                else:
                    list_user.append(str(item))
                    ___[str(item)]=""
                    globals()["pass{}".format(item)] = StringVar(main1, value='12345678')
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
                                if (str(getlogin())==str(item)) or item in system_user:
                                    globals()["checkbox{}{}".format(item, z)].config(state=DISABLED)
                                if (temp==1):
                                    ___[str(item)]+="1"
                                else:
                                    ___[str(item)]+="0"
                            break
            try:
                __=list_user[0]
                __=""
            except IndexError:
                popup("ProgramError","Program error! Couldn't find any users!")
            def onselect(evt="",khanh="",noload=0):
                global __,active,khanhh,temp2
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
                if (noload==0):
                    if (temp2==0):
                        #group
                        L22 = Label(main1, text="Group:", background=set_bg, foreground=set_fg)
                        L22.place_forget()
                        L22.place(x=130,y=22)

                        #active
                        L23 = Label(main1, text="Active:", background=set_bg, foreground=set_fg)
                        L23.place_forget()
                        L23.place(x=130,y=44)

                        #password
                        L24 = Label(main1, text="Password:", font=('Arial', 10, 'bold'), background=set_bg, foreground=set_fg)
                        L24.place_forget()
                        L24.place(x=130,y=145)

                        #warning
                        L24 = Label(main1, text="If the app requires Administrator, please tick Administrators for this user before run", font=('Arial', 8, 'bold'), background=set_bg, foreground='red')
                        L24.place_forget()
                        L24.place(x=128,y=180)
                        temp2=1
                    #user
                    NAME_USER_L = Label(main1, text="                                                                                                                                                          ", background=set_bg, foreground=set_bg)
                    NAME_USER_L.place_forget()
                    NAME_USER_L.place(x=130,y=0)
                    NAME_USER_L = Label(main1, text="User: {}".format(str(__)),font=('Arial', 10, 'bold'), background=set_bg, foreground=set_fg)
                    NAME_USER_L.place_forget()
                    NAME_USER_L.place(x=130,y=0)
                    
                    #group
                    x=0
                    for y in group:
                        for item in list_user:
                            globals()["checkbox{}{}".format(item, y)].place_forget()
                        globals()["checkbox{}{}".format(value, y)].place(x=175+x,y=20)
                        x+=120
                    
                    #active
                    for item in list_user:
                        globals()["active{}".format(item)].place_forget()
                    globals()["active{}".format(__)].place(x=175,y=42)

                    # apply
                    B22 = Button(main1, text = "Apply", command = lambda: apply_settings(__,group), background=set_button_bg, foreground=set_button_fg)
                    B22.place_forget()
                    B22.place(x=550,y=150)

                    # below list user
                    op_B2 = Button(main1, text = "Del", command = lambda: popup("DeleteUser",f"Do you want to delete [{__}]?",2,"_=Popen(\"net user \\\"{0}\\\" /delete && rmdir /q /s \\\"%systemdrive%\\\\Users\\\\{0}\\\"\",shell=True,stdin=PIPE,stdout=DEVNULL,stderr=DEVNULL); global mainerror,main1; mainerror.destroy(); main1.destroy(); tkinter_main()".format(str(__))), background='red', foreground=set_button_fg)
                    op_B2.place_forget()
                    op_B2.place(x=45,y=170)
                    if (str(getlogin())==str(__)) or __ in system_user:
                        op_B2["state"] = "disabled"
                        if (__ in system_user):
                            pass
                        else:
                            B22["state"] = "disabled"

                for item in list_user:
                    globals()["passw{}".format(item)].place_forget()
                if hide==0:
                    globals()["passw{}".format(__)].config(show='')
                else:
                    globals()["passw{}".format(__)].config(show='#')
                globals()["passw{}".format(__)].place(x=205,y=145)
                B23 = Button(main1, command = lambda: exec("global hide,khanhh\nif hide==0:\n    hide=1\nelse:\n    hide=0\nonselect(\"\",khanhh,1)"), background=set_button_bg, foreground=set_button_fg)
                if hide==0:
                    B23.config(text="Hide", width=10)
                else:
                    B23.config(text="Show", width=10)
                B23.place_forget()
                B23.place(x=400,y=142)

            listbox.bind('<<ListboxSelect>>', onselect)
            
            #below list user
            op_B1 = Button(main1, text = "Add", command = lambda: create_user(), background='green', foreground=set_button_fg)
            op_B1.place_forget()
            op_B1.place(x=3,y=170)
            op_B3 = Button(main1, text = "Reload", command = lambda: reload_main(main1), background='orange', foreground=set_button_fg)
            op_B3.place_forget()
            op_B3.place(x=80,y=170)
            
            #below program
            Label(mainbottom, text="Run:").pack(side = LEFT)
            Label(mainbottom, text="https://fb.me/khanh10a1").pack(side = RIGHT)
            E1 = Entry(mainbottom, bd=1, width=56)
            E1.insert(END, f"{systemdrive}\\Windows\\system32\\cmd.exe")
            E1.pack(side = LEFT)
            main1.bind('<Return>', lambda cmd: run_app(__,E1))
            main1.bind('<F5>', lambda cmd: reload_main(main1))
            Button(mainbottom, text = "Browse", command = lambda: browse_app(E1), background='green', foreground=set_button_fg).pack(side=LEFT)
            Button(mainbottom, text = "RUN", command = lambda: Thread(target=run_app, args=(__,E1)).start(), background='red', foreground=set_button_fg).pack(side=LEFT)
            main1.protocol("WM_DELETE_WINDOW", lambda: popup("ExitProgram",f"Do you want to exit?",2,"kill_process()"))
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
        from os import system, getpid, kill, getlogin, getenv, path, getcwd, mkdir, remove, rmdir
        from pathlib import Path
        from time import sleep
        from socket import gethostname
        from tkinter import *
        from tkinter import filedialog
        from random import choice
        import signal, hashlib
        try:
            from subprocess import DEVNULL
        except ImportError:
            from os import devnull
            DEVNULL = open(devnull, 'wb')
        global set_bg,set_fg,set_entry_bg,set_button_bg,set_button_fg,__,___,pid,active,systemdrive,hide,full_path,allow_program
        full_path=str("\\".join(str("/".join(str(getcwd()).split("\\"))).split("/"))+"\\core")
        pid = getpid()
        systemdrive = getenv("SystemDrive")
        hide=1
        allow_program=["exe","cmd","bat"]
        set_bg="white"
        set_fg="black"
        set_entry_bg="white"
        set_button_bg="#66453E"
        set_button_fg="white"
        ___={}
        active={}
        tkinter_main()
    else:
        print("This tool only work on Windows!")
        input()