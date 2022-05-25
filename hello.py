from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import binascii
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import os

e = int('010001', 16)  # exponente publico de la llave
n = int('B80E225FD13FE34B4F089B01DCF4232B55A488050848B2E81D06BDE6E201FBF6061C6D52B00BC70A32128F45755B2D4D1D3C5799C5D1E00965F892196044078503894F104A8822B1ECFD5C41BCEB03412C894552CB1854317C44205E9133A02D96DF441A0771073E1467A791BA5CB3FA4A7D97099DC4E7EC83B52423F32183B46C6E3083686AC1A4091780EF89FE9A690741141AC5B75D874A965A82B1825A8C4F605043307FF7593186F14A877563934686611F2FA79181443B5398E5271FAEDA35B728C19A49444723C54799A2CB2C272B9926E5DDA0440B3F6267BC3C80BC98C9A3FAEF0E7C21FC0A7CBB2960781D1724B5506C3845D14157E5667B3FA489', 16)
 # Modulo de la llave publica
randomkey = get_random_bytes(16)
key = DES3.adjust_key_parity(randomkey)
print("E: ", randomkey.hex())
# Construct a `RSAobj` with only ( n, e ), thus with only PublicKey

with open(os.path.expanduser('receiver.pem')) as public_key_file:
     public_key = RSA.importKey(public_key_file.read())
pubKey =  RSA.importKey(open("rsa_public_example.pem").read()) #RSA.construct( ( n, e ) )
#pubKey = rsaKey.publickey()
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")

# Export if needed
#pubKeyPEM = rsaKey.exportKey()

#print(pubKeyPEM.decode('ascii'))


print("KEY PARITY ", key.hex())
descipher = DES3.new(key,DES3.MODE_ECB)
checkValue = descipher.encrypt(bytes.fromhex('0000000000000000'))
print("check value: ", checkValue.hex())

# Encrypt message using RSA scheme
msg = bytes.fromhex('''00027F14F748E4804EF202B17BA24B3B3A1CCF7A0219913B98DF942EDCF239C367AF93C11B240EC6255924250291564D2C1BAA9CF0ACBB0D1E1988457C9C460CA6EF187AC450BE419417E5AE6EB715469A6B47D156E9F8245435F1AAE885E306A29FF1D8459A1DC42594C378A343C722E8D9254A4CC1ED2C515D64793052D1CA269E0D77A305B2926ECCC89F021748DFE01DA7BDA88D9FB2B2A32E922357DAB98193FAAD426874D42CB47E204A9B09C683963621B9FC7D62A945EEF752AB83E663BC937F08F15AAFC6D766950997C29A2456BB10BC4A703F704DED252E276E44EB52D8122496A4CBCAD3CD023DF82A000123456789ABCDEFFEDCBA9876543210''')  #randomkey
print("MSG: ", msg.hex())


#encryptor = PKCS1_v1_5.new(pubKey)
encryptor = PKCS1_v1_5.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", encrypted.hex())



# import os
# from Crypto.Cipher import PKCS1_v1_5
# from Crypto.PublicKey import RSA
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA
# from Crypto import Random
# from Crypto.Cipher import DES3

# with open(os.path.expanduser('receiver.pem')) as public_key_file:
#     public_key = RSA.importKey(public_key_file.read())


# transport_key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210') #get_random_bytes(16) 
# print("Transport key aleatoria: ", transport_key.hex())

# descipher = DES3.new(transport_key,DES3.MODE_ECB)
# msg = descipher.encrypt(bytes.fromhex('0000000000000000'))
# print("check value: ", msg.hex())

# cipher = PKCS1_v1_5.new(public_key)

# print("Cifrando con PKCS1#v1.5")

# # ciphertext =  bytes.fromhex('''1B249D03A980AA7A964E84A0D7883CA25FFB3957F3AB48C8A7988B934862D9BD
# # AB01118B7A20EE8FEA4B0E0AD3FB7DD09C14F154425375FC6F5DF1347F523AA0
# # 8C627CE741CEF83770DB37C69AE1F65BA8084B8B9B3FC8E6545B56F9F35A9860
# # CD945B78AAC807BDD8BAAB26B16BEE704E2D1D99E3BDC5A056234EF49F78561A
# # 8A7FB3C47759647CC3874EBBC8DDC1A85BE60FED769EBCDFADCDA9B60436B75B
# # F87E723DB62552916A6FB2B328368D3D7059973DBD1AF8E24E309FD6DC07684E
# # 46800B5326D757A7F795807F0229BAC17D127F0FF31D3ABEABA68D0363806107
# # F7CE4A0B82D63515AEF79BFFEF88D8A28D6457CEC9445F074334683EE03739BB''')
# ciphertext = cipher.encrypt(transport_key) 
# print("Transport Key cifrada bajo RSA publica: ", ciphertext.hex())

# private_key = RSA.importKey(open("private.pem").read())
# dsize = SHA.digest_size
# sentinel = Random.new().read(15+dsize)
# decipher = PKCS1_v1_5.new(private_key)
# #print("sentinel ", sentinel.hex())
# decipherText = decipher.decrypt(ciphertext,sentinel)
# if decipherText == sentinel : 
#     print("Ocurrio un error al descifrar la llave")
# else :
#     print("Descifrado de Transport Key Correcto")
#     print("Transport Key descifrada: ", decipherText.hex())