import requests
import sys
from bs4 import BeautifulSoup
import re
import urllib
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("-e",type=str, required = False,help = "exclude this uri. [-e /gnuboard/logout,/gnuboard/test]", metavar='[excluded url]' )
args = parser.parse_args()

i = 0
host = 'http://192.168.80.173/gnuboard/'
#host = 'http://192.168.70.136/'
#uriPattern = '(\/[a-zA-Z0-9\-\.][\/a-zA-Z0-9\-\.]*\0)'
#packetStruct= [uri,method,param]
packetList = [] # packet list for cralwing
dpacketList = [] # packet list done.

if args.e:
    excludeURL = args.e.split(',')
else:
    excludeURL = []

#print excludeURL

cook = {"PHPSESSID": "ipd1bvs522bc23e39i58pph8lc", "2a0d2363701f23f8a75028924a3af643": "MTkyLjE2OC44MC4x", "ck_font_resize_rmv_class": "", "ck_font_resize_add_class": ""} # http cookie
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Referer": "http://192.168.80.173/gnuboard/bbs/login.php", "Connection": "close", "Upgrade-Insecure-Requests": "1", "If-Modified-Since": "Thu, 06 Feb 2020 10:52:52 GMT"} # http headers

def dataToHashTable(data):  # change data (  a=b&c=d -> {'a':'b','c:'d'}  )
    dlist = data.split('&')
    result = {}

    for d in dlist:
        name = d.split('=')[0]
        value = d.split('=')[1]

        result[name] = value

    return result

def cralFormtag(soup): # cralwing "form" tag
    
    global packetList
    
    for i in range(0,len(soup.find_all('form'))):
        form = soup.find_all('form')[i]
        uri = form.get('action')

        if uri == None:
            uri = '/'
        else:
            uri = str(uri)
        
        method = str(form.get('method')).lower()
        

        data = ''
        for i in range(0,len(soup.find_all('input'))):
            ftype = soup.find_all('input')[i].get('type')
            ftype = str(ftype).lower()

            if ftype == 'text' or ftype == 'password' or ftype =='hidden':
                name = str(soup.find_all('input')[i].get('name'))
                value = (soup.find_all('input')[i].get('value'))
                if value == None:
                    value = ''
                else:
                    value = str(value)

                data = data +(name+'='+value+'&')
            
        if len(data)!=0:
            if data[-1] == '&':
                data = data[:-1]
        
        packet = [str(uri),str(method).lower(),urllib.unquote(data)]
        packetList.append(packet)
        
def cralIFrame(soup): # cralwing "a" tag
    global packetList
    
    for i in range(0,len(soup.find_all('iframe'))):
        a = soup.find_all('iframe')[i].get('src')
            
        try:
            if a== None:
                continue
            href = str(a)

            if '/' not in href:
                href = '/' + href
            
            if href.startswith('https://') or href.startswith('#') or href.startswith('javascript:'):
                pass

            else:
                if href.startswith(host):
                    href = href.replace(host,'')
                    if href ==None:
                        href = '/'
                    
                if '?' in href:
                    param = href[href.index('?')+1:]
                    packet = [href[:href.index('?')],'GET',urllib.unquote(param)] 
                    
                    if packet not in packetList:
                        packetList.append(packet)
                else:
                    packet = [href,'GET',''] 
                    
                    if packet not in packetList:
                        packetList.append(packet)

        except UnicodeEncodeError:
            pass
    
def cralFrame(soup): # cralwing "a" tag
    global packetList
    
    for i in range(0,len(soup.find_all('frame'))):
        a = soup.find_all('frame')[i].get('src')
            
        try:
            if a==None:
                continue
            href = str(a)

            if '/' not in href:
                href = '/' + href
            
            if href.startswith('https://') or href.startswith('#') or href.startswith('javascript:'):
                pass

            else:
                if href.startswith(host):
                    href = href.replace(host,'')
                    
                if '?' in href:
                    param = href[href.index('?')+1:]
                    packet = [href[:href.index('?')],'GET',urllib.unquote(param)] 
                    
                    if packet not in packetList:
                        packetList.append(packet)
                else:
                    packet = [href,'GET',''] 
                    
                    if packet not in packetList:
                        packetList.append(packet)

        except UnicodeEncodeError:
            pass

def cralFormtag(soup): # cralwing form tag

    global host 
    global packetList
    
    for i in range(0,len(soup.find_all('form'))):
        form = soup.find_all('form')[i]
        uri = (form.get('action'))

        if uri == None:
            uri = '/'
        else:
            uri = str(uri)
        
        if host in uri:
            uri = uri.replace(host,'')
        method = str(form.get('method')).lower()

        data = ''
        for i in range(0,len(soup.find_all('input'))):
            ftype = soup.find_all('input')[i].get('type')
            ftype = str(ftype).lower()

            if ftype == 'text' or ftype == 'password' or ftype =='hidden':
                name = str(soup.find_all('input')[i].get('name'))

                value = (soup.find_all('input')[i].get('value'))
                if value == None:
                    value = ''
                else:
                    value = str(value)

                data = data +(name+'='+value+'&')
            
        if len(data)!=0:
            if data[-1] == '&':
                data = data[:-1]
        
        packet = [str(uri),str(method),urllib.unquote(data)]
        packetList.append(packet)
        
def cralAtag(soup): # cralwing a tag
    global packetList
    
    for i in range(0,len(soup.find_all('a'))):
        a = soup.find_all('a')[i].get('href')
            
        try:
            if a==None:
                continue
            href = str(a)

            if '/' not in href:
                href = '/' + href
            
            if href.startswith('https://') or href.startswith('#') or href.startswith('javascript:'):
                pass

            else:
                if href.startswith(host):
                    href = href.replace(host,'')

                if '?' in href:
                    param = href[href.index('?')+1:]
                    packet = [str(href[:href.index('?')]),'get',urllib.unquote(param)] 
                    
                    if packet not in packetList:
                        packetList.append(packet)
                else:
                    packet = [str(href),'get',''] 
                    
                    if packet not in packetList:
                        packetList.append(packet)

        except UnicodeEncodeError:
            pass

def cralHTML(soup):
    cralAtag(soup)
    cralFormtag(soup)
    cralIFrame(soup)
    cralFrame(soup)
   
def cralwing(): # cralwing
    global host
    global i
    global soup
    global dpacketList
    global packetList
    global cook
    global headers
    global excludeURL 

    #print i
    packet = packetList[i]

    uri = packet[0]

    if uri in excludeURL:
        i+=1
        dpacketList.append(packet)
        return
        
    if packet in dpacketList:
        i+=1
        return
    else:
        dpacketList.append(packet)

    #print uri
    method = packet[1].upper()
    param = packet[2]

    if method == 'GET':

        if len(param)==0:    
            req = requests.get(('%s'%host)+uri,cookies = cook,headers = headers)
            resp = req.text
            soup = BeautifulSoup(resp,'html.parser')
            cralHTML(soup)
        else:
            req = requests.get(('%s'%host)+uri+'?'+param,cookies = cook,headers = headers)
            resp = req.text
            soup = BeautifulSoup(resp,'html.parser')
            cralHTML(soup)
    
    else: # method = POST
        url = host+uri
        cook = {}
        headers = {}
        data = dataToHashTable(param)
        req = requests.post(url,headers = headers, cookies = cook,data = data)
        resp = req.text
        soup = BeautifulSoup(resp,'html.parser')
        cralHTML(soup)
    
    i += 1

req = requests.get(host+'index.php') # first cralwing start page.
#req = requests.get(host) # first cralwing start page.
html = req.text
header = req.headers
status = req.status_code

is_ok = req.ok
soup = BeautifulSoup(html,'html.parser')
soup.find_all('a')

cralHTML(soup)

while True:
    try:
        #print i
        cralwing()
    except Exception as e:
        print e

        for i in range(0,len(dpacketList)):
            print dpacketList[i]

        print len(dpacketList) 

        sys.exit()
