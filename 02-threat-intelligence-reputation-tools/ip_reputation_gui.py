from tkinter import *
import pandas as pd
import time
import requests
import json

def login():
    #getting form data
    vt_authkey = Auth_Key_VT.get()
    path = File_Path.get()
    authkeyabuse = Auth_Key_Abuseipdb.get()

    #applying empty validation
    if vt_authkey == '' or path == '' or authkeyabuse == '':
        message.set(" ** fill the empty field!!!")
    else:
        GetResult(vt_authkey, path, authkeyabuse)

def GetResult(vt_authkey, path, authkeyabuse):
    try:
        df = pd.read_excel(path, sheet_name='IP')
        file_list = dict(df['IP']) 
        file_to_save = []
        list_count = len(file_list)
        print("You have selected : " + str(list_count) + " IP")
        time.sleep(2)
        print(" Please wait, We are working on it  .....")

        for f in file_list:
            op_abuseisp, op_abusedomain, op_abusescore = abuseipdb(file_list[f], authkeyabuse)
            op_vtscore = virustotal(file_list[f], vt_authkey)
            file_to_save.append([file_list[f], op_abusedomain, op_abuseisp, op_abusescore, op_vtscore])
    except Exception as e:
        splash_screen(e)

    print(len(file_to_save))

    if len(file_to_save) == 0:
        file_to_save = ['An Error occurred: Please check your API keys and File path and run it again']
        pd.DataFrame(file_to_save, columns=['IP']).to_excel(path, sheet_name='IP', index=False)
    else:
        pd.DataFrame(file_to_save, columns=['IP', 'Domain', 'ISP', 'AbuseIPDB', 'VirusTotal']).to_excel(path, sheet_name='IP', index=False)
        print("**************************************")
        completed_text = "Your file is ready, please check"
        splash_screen(completed_text)

def abuseipdb(input_url, authkeyabuse):
    #API Details
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': authkeyabuse
    }
    querystring = {'ipAddress': input_url}

    #Calling IP
    try:
        response = requests.request(method='GET', url=abuse_url, headers=headers, params=querystring)
        decodedResponse = json.loads(response.text)
        abuse_isp = decodedResponse['data']['isp']
        abuse_domain = decodedResponse['data']['domain']
        abuse_score = decodedResponse['data']['abuseConfidenceScore']
        return abuse_isp, abuse_domain, abuse_score
    except Exception as e:
        return e

def virustotal(input_url, vt_authkey):
    #API Details
    vt_url = "https://www.virustotal.com/api/v3/ip_addresses"
    headers = {
        "accept": "application/json",
        "x-apikey": vt_authkey
    }
    api_vt_url = str('/'.join([str(vt_url), str(input_url)]))

    #Getting Reputation
    try:
        response = requests.get(api_vt_url, headers=headers)
        reputation_data = json.loads(response.text)
        try:
            Total_score = int(reputation_data['data']['attributes']['last_analysis_stats']['harmless']) + \
                          int(reputation_data['data']['attributes']['last_analysis_stats']['malicious']) + \
                          int(reputation_data['data']['attributes']['last_analysis_stats']['suspicious']) + \
                          int(reputation_data['data']['attributes']['last_analysis_stats']['undetected']) + \
                          int(reputation_data['data']['attributes']['last_analysis_stats']['timeout'])
            Malicious_score = int(reputation_data['data']['attributes']['last_analysis_stats']['malicious'])
            vt_score = str('/'.join([str(Malicious_score), str(Total_score)]))
        except:
            vt_score = reputation_data['error']['message']

        return vt_score
    except Exception as e:
        return e

def splash_screen(error):
    # Create a new window for the splash screen
    splash_window = Tk()
    splash_window.geometry("300x300")
    splash_window.title("IP Reputation Tool")
    error = str(error)
    Label(splash_window, width="400", height="400", text=error, bg="orange", fg="white").pack()
    Label(main_screen, text="Thank you :) \n Faced any challenge connect over slack @Sanjot").place(x=139, y=192)

def Loginform():
    global main_screen
    main_screen = Tk()
    # Setting title of screen
    main_screen.title("IP Reputation Tool")
    # Setting height and width of screen
    main_screen.geometry("600x300")
    # declaring variable
    global message
    global Auth_Key_VT
    global File_Path
    global Auth_Key_Abuseipdb
    global error
    Auth_Key_VT = StringVar()
    Auth_Key_Abuseipdb = StringVar()
    File_Path = StringVar()
    message = StringVar()
    # Creating layout of login form
    Label(main_screen, width="300", text="Please enter details below", bg="orange", fg="white").pack()
    # Auth_Key_VT Label
    Label(main_screen, text="Auth_Key_VirusTotal").place(x=20, y=40)
    # Auth_Key_VT textbox
    Entry(main_screen, textvariable=Auth_Key_VT, show="*").place(x=170, y=42)
    # Auth_Key_Abuseipdb Label
    Label(main_screen, text="Auth_Key_Abuseipdb").place(x=20, y=120)
    # Auth_Key_Abuseipdb textbox
    Entry(main_screen, textvariable=Auth_Key_Abuseipdb, show="*").place(x=170, y=122)
    # File Path Label
    Label(main_screen, text="File Path").place(x=20, y=160)
    # File Path textbox
    Entry(main_screen, textvariable=File_Path).place(x=170, y=162)
    # Label for displaying login status[success/failed]
    Label(main_screen, text="", textvariable=message).place(x=139, y=192)
    # Login button
    Button(main_screen, text="Calculate Reputation", width=20, height=1, bg="orange", command=login).place(x=179, y=222)
    main_screen.mainloop()

# calling function Loginform
Loginform()
