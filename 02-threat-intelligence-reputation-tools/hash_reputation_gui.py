from tkinter import *
import pandas as pd
import time
import virustotal_python
from pprint import pprint

#defining login function
def login():
    #getting form data
    vt_authkey=Auth_Key_VT.get()
    path=File_Path.get()
    #applying empty validation
    if vt_authkey=='' or path=='':
        message.set("fill the empty field!!!")
    else:
        VT_Hash(vt_authkey,path)
        
      

def VT_Hash(vt_authkey,path):

    try:
        df = pd.read_excel (path,sheet_name='Hash')
        file_list = df['Hash'].values.tolist()
        list_count = len(file_list)
        print("You have selected : " + str(list_count) + " hashes for the conversion")
        time.sleep(2)
        print(" Please wait, We are working on it  .....")
        time.sleep(2)
        
    except Exception as e:
        splash_screen(e)
        

    file_to_save = []
    with virustotal_python.Virustotal(vt_authkey) as vtotal:
        for f in file_list:
            try:
                resp = vtotal.request(f"files/{f}")
                md5_hash = resp.data['attributes']['md5']
                sha_256_hash=resp.data['attributes']['sha256']
                mal_score = int(resp.data['attributes']['last_analysis_stats']['malicious'])
                #try:
                trid_list = resp.data['attributes']['trid']
                file_type_str = ''
                for tr in trid_list:
                    file_type_str += tr['file_type'] + ', ' 
                    tr_id= file_type_str

                #except Exception as e :
                       # tr_id="not found"   

                Total_score = mal_score + int(resp.data['attributes']['last_analysis_stats']['undetected'])
                #pprint(mal_score)
                #pprint(Total_score)
                reputation = str('/'.join([str(mal_score),str(Total_score)]))
                #pprint(reputation)
                #pprint("MD5 Value :  " + str(md5_hash))
                file_to_save.append([f, md5_hash,sha_256_hash, reputation,tr_id])
            except virustotal_python.VirustotalError as err :
                not_found="Not Found"
                file_to_save.append([f, not_found, not_found, err,not_found])
                if str(err).__contains__("404") :
                    print("404 Error")
                else :
                    splash_screen(err)
                    break


                              
    pd.DataFrame(file_to_save, columns=['Hash', 'MD5','SHA_256', 'Reputation','TR-ID']).to_excel(path, sheet_name='Hash', index=False)
    print("**************************************")
    print("Your file is ready, please check")  
    error="Thank You \n Your file is ready, please check"
    splash_screen(error)
    
                         

def splash_screen(error):
    # Create a new window for the splash screen
    splash_window = Tk()
    splash_window.geometry("300x300")
    splash_window.title("Hash Reputation Tool")
    error=str(error)
    Label(splash_window,width="400", height="400", text=error, bg="orange",fg="white").pack()
    Label(main_screen, text="Thank you :) \n Faced any challenge connect over slack @Sanjot").place(x=75,y=110)

    

    #Create a label that displays the splash screen message
    #splash_label = Tk.Label(splash_window, text="Your File is ready, please check ")
    #splash_label.pack(pady=50)
     


#defining loginform function
def Loginform():
    global main_screen
    main_screen = Tk()
    #Setting title of screen
    main_screen.title("Hash Reputation Tool")
    #setting height and width of screen
    main_screen.geometry("400x250")
    #declaring variable
    global  message
    global Auth_Key_VT
    global File_Path
    global error
    Auth_Key_VT = StringVar()
    File_Path = StringVar()
    message=StringVar()
    #Creating layout of login form
    Label(main_screen,width="300", text="Please enter details below", bg="orange",fg="white").pack()
    #Auth_Key_VT Label
    Label(main_screen, text="Auth_Key_VirusTotal").place(x=20,y=40)
    #Auth_Key_VT textbox
    Entry(main_screen, textvariable=Auth_Key_VT,show="*").place(x=170,y=42)
    #File_Path Label
    Label(main_screen, text="File Path").place(x=20,y=80)
    #File_Path textbox
    Entry(main_screen, textvariable=File_Path ).place(x=170,y=82)
    #Label for displaying login status[success/failed]
    Label(main_screen, text="",textvariable=message).place(x=95,y=110)
    #Login button
    Button(main_screen, text="Calculate Reputation", width=20, height=1, bg="orange",command=login).place(x=109,y=150)
    main_screen.mainloop()
#calling function Loginform
Loginform()