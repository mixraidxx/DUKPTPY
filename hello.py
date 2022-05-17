
import os
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import DES3
import zlib
import binascii


with open(os.path.expanduser('public_mpos.pem')) as public_key_file:
    public_key = RSA.importKey(public_key_file.read())


transport_key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210') #get_random_bytes(16) 
print("Transport key aleatoria: ", transport_key.hex())

descipher = DES3.new(transport_key,DES3.MODE_ECB)
msg = descipher.encrypt(bytes.fromhex('0000000000000000'))
print("check value: ", msg.hex())

cipher = PKCS1_v1_5.new(public_key)

print("Cifrando con PKCS1#v1.5")

#ciphertext =  bytes.fromhex('''06ACBF1D8DCADCDC3A734F016BAB8DACD7136477A7BB0E5D4C3DD03C005F6A192BEB9E121B9A0FBA110E9A6CD8EDF0DB6571DB399C2F51DE8B3C747FB627715C23AC946C323D55A3D9515CD14AC1DFC2F4D8E133F1F4CD29DA5C006D6CDB1D15869278D48E0084A19D5BDCDEED4A0DD1E836ACD0CAD2B2C2CCC452793005D6C9ECFF913E7C0CFE39F7ACB3CDBD3012CE8F0DC7A2D15FD3A5ACCB16A7BDC58379F3C159C8857708620211E2049922F654A4AD466C2035A9DBB066C572C55311117723035B1139B311B6FFD615B44BDEF365D7065C7A306BFC561BA733C4ACAE556189491975274056F574AF401109A0BE0C4062D7A98F74A46E18403ED88026AF''')
ciphertext = cipher.encrypt(transport_key) 
print("Transport Key cifrada bajo RSA publica: ", ciphertext.hex())

private_key = RSA.importKey(open("private_mpos.pem").read())
dsize = SHA.digest_size
sentinel = Random.new().read(15+dsize)
decipher = PKCS1_v1_5.new(private_key)
#print("sentinel ", sentinel.hex())
decipherText = decipher.decrypt(ciphertext,sentinel)
if decipherText == sentinel : 
    print("Ocurrio un error al descifrar la llave")
else :
    print("Descifrado de Transport Key Correcto")
    print("Transport Key descifrada: ", decipherText.hex())