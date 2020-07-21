#! /usr/bin/python3
import os
import socket
import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

class Sender():

	blocksize = 16
	buf = 1024
	
	def __init__(self, filename, lhost = "127.0.0.1", lport = 4444):
		self.filename = filename
		
		self.lhost = lhost
		self.lport = lport
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.bind((self.lhost, self.lport))
		
		self.aeskey = Random.new().read(self.blocksize)
		self.aesiv = Random.new().read(self.blocksize)
		
		rsa = RSA.generate(1024, Random.new().read)
		self.private = rsa.exportKey()
		self.public = rsa.publickey().exportKey()
		
		self.__fileHandler()

		
	def __fileHandler(self):
		#读取文件基本信息
		self.filesize = os.path.getsize(self.filename)
		print("[*] FileName: %s\n[*] Size: %s bytes"%(self.filename, self.filesize))
		
		#对文件进行流式加密并计算摘要
		md5 = MD5.new()
		cipher = AES.new(self.aeskey, AES.MODE_CBC, self.aesiv)
		with open(self.filename, "rb") as f1:
			with open("enc_" + self.filename, "wb") as f2:
				for _ in range(self.filesize // self.buf):
					filedata = f1.read(self.buf)
					md5.update(filedata)
					enc_filedata = cipher.encrypt(filedata)
					f2.write(enc_filedata)
					
				filedata = f1.read(self.buf)
				md5.update(filedata)
				padding = self.blocksize - (self.filesize % self.buf) % self.blocksize
				filedata += chr(padding).encode('utf8') * padding
				enc_filedata = cipher.encrypt(filedata)
				f2.write(enc_filedata)
		print("[*] File encrypted")
		
		#对摘要进行签名
		rsakey = RSA.importKey(self.private)
		signer = Signature_pkcs1_v1_5.new(rsakey)
		self.signature = signer.sign(md5)
		print("[*] File digest signed")
		
	def start(self):
		self.server.listen(10)
		print("[+] Server listening on %s:%s"%(self.lhost, self.lport))
		print("=" * 48)
		while True:
			print("[*] Waiting for the receiver to connect...")
			client, addr = self.server.accept()
			print("[+] Conneted from %s:%s"%(addr[0], addr[1]))
			
			#接收客户端公钥
			print("[*] Receive the client public key...")
			clientPublicKey = client.recv(1024)
			print("[+] Done")
			
			#对AES密钥进行加密
			print("[*] Encrypt the key of aes...")
			rsakey = RSA.importKey(clientPublicKey)
			cipher = Cipher_pkcs1_v1_5.new(rsakey)
			enc_key = cipher.encrypt(self.aeskey)
			print("[+] Done")
			
			#通过json传输摘要签名、公钥等信息
			header_dict = {
				"filename" : self.filename,
				"filesize" : self.filesize,
				"buf" : self.buf,
				"signature" : base64.b64encode(self.signature).decode("utf8"),
				"serverPublicKey" : base64.b64encode(self.public).decode("utf8"),
				"blocksize" : self.blocksize,
				"enc_aeskey" : base64.b64encode(enc_key).decode("utf8"),
				"aesiv" : base64.b64encode(self.aesiv).decode("utf8")
			}
			header_json = json.dumps(header_dict)
			client.send(header_json.encode("utf8"))
			
			#发送加密文件
			with open("enc_" + self.filename, "rb") as f:
				print("[*] File sending...")
				while True:
					filedata = f.read(self.buf)
					if not filedata:
						break
					client.send(filedata)
				print("[+] Done")
			client.close()
			print("=" * 48)
			
		self.server.close()



if __name__ == '__main__':
	server = Sender("big.txt")
	server.start()
