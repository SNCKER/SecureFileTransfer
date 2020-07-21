#! /usr/bin/python3
import socket
import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5


class Receiver():

	def __init__(self, rhost, rport = 4444):
		self.rhost = rhost
		self.rport = rport
		
		rsa = RSA.generate(1024, Random.new().read)
		self.private = rsa.exportKey()
		self.public = rsa.publickey().exportKey()
		
	def recvFile(self):
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.connect((self.rhost, self.rport))
		#发送公钥给服务器
		client.send(self.public)
		
		#接收服务器公钥、摘要签名等信息
		header_json = client.recv(1024).decode("utf8")
		header_dict = json.loads(header_json)
		
		#使用服务器公钥提取AES密钥
		rsakey = RSA.importKey(self.private)
		cipher = Cipher_pkcs1_v1_5.new(rsakey)
		aeskey = cipher.decrypt(base64.b64decode(header_dict['enc_aeskey']), None)
		aesiv = base64.b64decode(header_dict['aesiv'])
		
		#接收加密文件，同时进行解密和摘要计算
		print("[*] Start receiving file...")
		with open(header_dict['filename'], "wb") as f:
			md5 = MD5.new()
			cipher = AES.new(aeskey, AES.MODE_CBC, aesiv)
			for _ in range(header_dict['filesize'] // header_dict['buf']):
				filedata = client.recv(header_dict['buf'])
				dec_filedata = cipher.decrypt(filedata)
				md5.update(dec_filedata)
				f.write(dec_filedata)
				print("[*] Receiving...%0.2f%%"%((_ + 1) * 1024 / header_dict['filesize'] * 100))
				
			filedata = client.recv(header_dict['buf'])
			dec_filedata = cipher.decrypt(filedata)
			md5.update(dec_filedata[:-dec_filedata[-1]])
			f.write(dec_filedata[:-dec_filedata[-1]])
			print("[*] Receiving...100.00%\n[+] Done")
		
		#验证签名
		print("[*] Verify in signature...")
		rsakey = RSA.importKey(base64.b64decode(header_dict['serverPublicKey']))
		signer = Signature_pkcs1_v1_5.new(rsakey)
		verify = signer.verify(md5, base64.b64decode(header_dict['signature']))
		if verify:
			print("[+] Correct!")
		else:
			print("[-] Error! Please try to receive the file again!")

if __name__ == '__main__':
	client = Receiver("127.0.0.1")
	client.recvFile()
