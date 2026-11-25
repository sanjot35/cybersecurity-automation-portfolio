import pandas as pd
import time
import requests
import sys
import getopt
import virustotal_python
from pprint import pprint

def send_slack_message(message):
    payload = '{"text":"%s"}' % message
    response = requests.post('https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK_PLACEHOLDER',data = payload)
    print(response.text)


df = pd.read_excel ("./input.xlsx")
#print (df['file_hash'])

file_list = df['file_hash'].values.tolist()
list_count = len(file_list)
print("You have selected : " + str(list_count) + " hases for the conversion")
time.sleep(2)
print(" We are working on it .....")
time.sleep(2)

vt_auth1 = "YOUR_VIRUSTOTAL_API_KEY"

file_to_save = []
file_md5=[]
with virustotal_python.Virustotal(vt_auth1) as vtotal:
    for f in file_list:
        pprint("Hash Value : " + str(f))
        resp = vtotal.request(f"files/{f}")
        md5_hash = resp.data['attributes']['md5']
        pprint("MD5 Value :  " + str(md5_hash))
        file_md5.append(md5_hash)
        file_to_save.append([f, md5_hash])

pd.DataFrame(file_to_save, columns=['file_hash', 'md5']).to_csv('file_to_hash.csv', index=False)
print("Your file is ready, please check")
cf=pd.DataFrame(file_md5)
lf = cf.to_string(index=False)
hf=str(lf)
print(hf)
fh = "Your MD5 Hash Values are below :  " + lf
lst_str = str(file_md5)[1:-1] 
send_slack_message(fh)



