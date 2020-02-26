import ssl
import base64
from socket import socket, AF_INET, SOCK_STREAM
import os
from datetime import datetime


cert_file="temp.pem"
if os.path.exists(cert_file):
       os.remove(cert_file)
cc = socket(AF_INET, SOCK_STREAM)
cc.connect(("<servername>", 389))
# ANS1 STARTTLS OID 1.3.6.1.4.1.1466.20037
# The correct way to do is is to build ASN1 with pyans1. This was copied from wireshark as a hex dump
bytes1=bytearray.fromhex('30 1d 02 01 01 77 18 80 16 31 2e 33 2e 36 2e 31 2e 34 2e 31 2e 31 34 36 36 2e 32 30 30 33 37')
#send ANS1 STARTTLS to the LDAP server
cc.send(bytes1)
recv1 = cc.recv(1024)
try:
    #Wrap the socket to do the ssl handshake
    scc = ssl.wrap_socket(cc, ssl_version=ssl.PROTOCOL_SSLv23)
except:
   print("error")
#Close the connection once the ssl handshake is done. We have the Certificate.   
cc.close()
#convert the certificate to PEM format
cert=ssl.DER_cert_to_PEM_cert(scc.getpeercert(binary_form=True))
#write it to a file
f=open(cert_file,"a")
f.write(cert)
f.close()
#test_decode_cert is undocumented but is build a Dict of the certificate structure
temp=ssl._ssl._test_decode_cert(cert_file)
d=datetime.strptime(temp['notAfter'], r'%b %d %H:%M:%S %Y %Z')
print(d)  #prints the expire date on the certificate
