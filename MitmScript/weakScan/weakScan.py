"""
This example shows how to send a reply from the proxy immediately
without sending any data to the remote server.
"""
# -*- coding: utf-8 -*-
import sys
import json
import urllib
import base64
import urllib.parse
import requests
from mitmproxy import http

# setting value  #
urlList = [] dlist = []
testorigin = 'https://kswtest.com'
testurl = 'kswtest.net'
olist = [] #origin test list
alist = [] #auth test list
authInfo = 'Cookie'
authScanEanble = 0
hiddenParam='returnUrl=https://kswtest.com'
hiddenScanEnable = 0
hlist = [] #hidden scan list

originFile ='C:\\Users\\ksw97\Desktop\\study\\mitmScript\\weakScan\\originResult.txt'
#originFile = 'D:\\Study\\mitmScript\\weakScan\\originResult.txt'
xssFile = 'C:\\Users\\ksw97\Desktop\\study\\mitmScript\\weakScan\\xssResult.txt'
#xssFile = 'D:\\Study\\mitmScript\\weakScan\\xssResult.txt'
authFile = 'C:\\Users\\ksw97\Desktop\\study\\mitmScript\\weakScan\\authResult.txt'
#authFile = 'D:\\Study\\mitmScript\\weakScan\\authResult.txt'
hiddenFile = 'C:\\Users\\ksw97\Desktop\\study\\mitmScript\\weakScan\\hiddenResult.txt'
#hiddenFile = 'D:\\Study\\mitmScript\\weakScan\\hiddenResult.txt'

# setting end  #

def hiddenParamScan(flow):
    reqUrl = flow.request.url
    turl = reqUrl.split('?')[0]

    if turl in hlist:
        return
    else:
        hlist.append(turl)

    method = flow.request.method
    
    result = {}
    for h in hnames: # header parsing
        result[h] = flow.request.headers[h]
    
    if '?' in reqUrl:
        reqUrl = reqUrl+'&'+hiddenParam
    else:
        reqUrl = reqUrl+'?'+hiddenParam
    
    if method=='GET':
        resp = requests.get(reqUrl,headers = result)
        content = resp.text
        
        if hiddenParam.split('=')[1] in content:
            print('[+] %s uses hidden Param..!!!\n'%reqUrl)
            f = open(hiddenFile,'a')
            f.write('[+] %s uses hidden Param..!!!\n'%reqUrl)
            f.close()
            
#auth scan : send same request without authorization header.
def authScan(flow,clen):
    alist.append(flow.request.url)
    reqUrl = flow.request.url
    method = flow.request.method
    
    hnames = (flow.request.headers).keys()
    result = {}
    
    for h in hnames:
        result[h] = flow.request.headers[h]
    
    try:
        result.pop(authInfo)
    except:
        pass

    if method=='GET':
        resp = requests.get(reqUrl,headers=result)
        if abs(len(resp.text)-clen)<=5:
            print('[+] %s may be not check Authentication..!!!'%reqUrl)
            f = open(authFile,'a')
            f.write('[+] %s may be not check Authentication..!!!\n'%reqUrl)
            f.close()
    else: # method = POST
        if b'{' in flow.request.content and b'}' in flow.request.content: # json format
            try:
                resp = requests.post(reqUrl,headers=result,json=json.loads(flow.request.content))
                if abs(len(resp.text)-clen)<=5:
                    print('[+] %s may be not check Authentication..!!!'%reqUrl)
                    f = open(authFile,'a')
                    f.write('[+] %s may be not check Authentication..!!!\n'%reqUrl)
                    f.close()
            except:
                resp = requests.post(reqUrl,headers=result,data=flow.request.content)
                if abs(len(resp.text)-clen)<=5:
                    print('[+] %s may be not check Authentication..!!!'%reqUrl)
                    f = open(authFile,'a')
                    f.write('[+] %s may be not check Authentication..!!!\n'%reqUrl)
                    f.close()

# send craft origin.
def originScan(flow):
    olist.append(flow.request.url)
    reqUrl = flow.request.url
    method = flow.request.method
    url = flow.request.url
    
    hnames = (flow.request.headers).keys()
    result = {}
    
    for h in hnames:
        if 'h'.upper()=='ORIGIN':
            continue
        result[h] = flow.request.headers[h]
    
    result['Origin']=testorigin
    
    if method=='GET':
        resp = requests.get(url,headers = result)
        rheader = (resp.headers)
    
        try:
            if rheader['Access-Control-Allow-Origin']==testorigin:
                print('[*] SOP Vulnerabity Detect...!! - %s'%flow.request.url)
                f = open(originFile,'a')
                f.write('[*] SOP Vulnerabity Detect...!! - %s'%flow.request.url)
                f.close()
        except Exception as e:
            print('[-] Sop error occured')
            print(e)
            pass

def response(flow: http.HTTPFlow) -> None:

    if testurl in flow.request.pretty_url and flow.request.url not in urlList:
        '''
        Reflected XSS Weak Scan
        '''
        paramList = []
        getP = flow.request.query
        postP = flow.request.content
        print('[*] :', flow.request.pretty_url)
        
        for a in flow.request.query:
            if flow.request.query[a] in flow.response.text:
                f = open(xssFile,'a')
                wtmp = "[*] %s : Get Parameter %s is Reflected..!!\n"%(flow.request.url.split('?')[0],a)
                f.write(wtmp)
                urlList.append(flow.request.url)
                print(wtmp)
                f.close()
                
        #post param

        if b'{' in flow.request.content and b'}' in flow.request.content:
            try: # json POST Param
                pBody = json.loads(flow.request.content)
                
                for a in pBody:
                    if pBody[a] in flow.response.text:
                        f = open(xssFile,'a')
                        wtmp = "[*] %s : POST Parameter %s is Reflected..!!\n"%(flow.request.url.split('?')[0],a)
                        f.write(wtmp)
                        print(wtmp)
                        f.close()
                
            except Exception as e: # no json POST Param
                pBody = flow.request.content
                pBody = pBody.decode('utf-8')
                pBody = pBody.split('&')
                
                for a in pBody:
                    param = a.split('=')
                    if param[1] in flow.response.text:
                        f = open(xssFile,'a')
                        wtmp = "[*] %s : POST Parameter %s is Reflected..!!\n"%(flow.request.url.split('?')[0],param[0])
                        f.write(wtmp)
                        print(wtmp)
                        f.close()
               
        else:
            pBody = flow.request.content
            pBody = pBody.decode('utf-8')
            pBody = pBody.split('&')
                
            for a in pBody:
                try:
                    param = a.split('=')
                    if param[1] in flow.response.text:
                        f = open(xssFile,'a')
                        wtmp = "[*] %s : POST Parameter %s is Reflected..!!\n"%(flow.request.url.split('?')[0],param[0])
                        f.write(wtmp)
                        print(wtmp)
                        f.close()
                except Exception as e:
                    print(e)
                    
        '''
        Weak Origin Scan
        request Module + Add origin header
        '''
        if flow.request.url not in olist:
            originScan(flow)
            
        '''
        Auth Scan
        request Module + Remove auth Header
        '''

        if authScanEanble and flow.request.url not in alist:
            authScan(flow,len(flow.response.content))
            
        
        
