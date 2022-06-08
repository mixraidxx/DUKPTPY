"""                                 Shree Krishnaya Namaha 
This is an implementation of DUKPT algorithm in Python.
The reference for this implementation is the excellent write up found here:
https://www.parthenonsoftware.com/blog/how-to-decrypt-magnetic-stripe-scanner-data-with-dukpt/
This module converts the steps mentioned in the above link to Python code.
"""
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from bitstring import BitArray

RESET_COUNTER_MASK = BitArray(hex="FFFFFFFFFFFFFFE00000")
COUNTER_MASK = BitArray(hex="000000000000001FFFFF")
PIN_MASK = BitArray(hex="00000000000000FF00000000000000FF")
C = BitArray(hex='0xC0C0C0C000000000C0C0C0C000000000')
DEK_MASK = BitArray(hex="0000000000FF00000000000000FF0000")
DATA_MASK = BitArray(hex='0x0000000000FF00000000000000FF0000')



class Dukpt:
    """This class provides methods for generating the Future keys as well 
    as IPEK keys after setting the BDK and KSN """
    def __init__(self):
        self.bdk = None
        self.ipek = None
        self.ksn = None

    def set_bdk(self, bdk):
        """Sets the Base Derivation Key for the current DUKPT calculator instance"""
        if len(bdk) != 32:
            raise ValueError("The BDK should be 16 bytes wide")
        self.bdk = BitArray(hex=bdk)
        print("BDK: ", self.bdk)

    def set_ksn(self, ksn):
        """Sets the KSN (Key serial number) for the DUKPT calculator"""
        if len(ksn) != 20:
            raise ValueError("KSN has to be a 10 byte value")
        self.ksn = BitArray(hex=ksn)
        print("KSN: ", self.ksn)

    @staticmethod
    def get_complete_bdk(bdk):
        return bdk + bdk.bytes[0:8]

    def compute_ipek(self):
        """Computes the initial pin encryption key"""
        cleared_ksn = self.ksn & RESET_COUNTER_MASK
        print("cleared ksn: ", cleared_ksn)
        ksn = cleared_ksn.bytes[0:8]
        print("KSN: ", str(BitArray(bytes = ksn)))

        bdk = Dukpt.get_complete_bdk(self.bdk)
        cipher = DES3.new(bdk.bytes, DES3.MODE_ECB)
        left_register = cipher.encrypt(ksn)
        print("left register: ", str(BitArray(bytes=left_register)))

        c_masked_bdk = self.bdk ^ C
        bdk = Dukpt.get_complete_bdk(c_masked_bdk)
        cipher = DES3.new(bdk.bytes, DES3.MODE_ECB)
        right_register = cipher.encrypt(ksn)
        self.ipek = BitArray(bytes=left_register + right_register)
        return self.ipek
    
    def generateDataKey(self):
        xor = self.ipek ^ DATA_MASK
        cipher = DES3.new(xor.bytes, DES3.MODE_ECB)
        datakey = cipher.encrypt(xor.bytes)
        return BitArray(bytes= datakey)



def main():
    dukpt = Dukpt()
    bdk = "00112233445566778899AABBCCDDEEFF"
    ksn = "0102012345678AE00000"
    dukpt.set_bdk(bdk)
    dukpt.set_ksn(ksn)
    ipek = dukpt.compute_ipek()
    print (str(ipek))
    datakey = dukpt.generateDataKey()
    print(str(datakey))

main()


#bdk = 00112233445566778899AABBCCDDEEFF
#ksn = 0102012345678AE00000
#ipek = FDB5C138D31DDCAA6C5DC76827EF487E

# import zlib

# crc32 = hex(zlib.crc32(b'870DAA7E092CD56AF447C86C2C27BE08534C58F65E09EBE64C93C2EB6DC6D2BF90E99327D1B30BAB4D6967BF97A97E1B29AB5AC7DB44BA15BB565460606BFD29E5CB6DD20B4E35910C9F83BBD0594B0068D47E4B064D70D5D6FD098D5571E3A0495D01E2696487CD72FF48CCDFB38CD423B2A2EA7E6EFA9F3881F8981AD5FE328C28B9AFE61E464D4D83CB1FC1BC272F80CCD5DA09C01689F7FEE0903B38CBCC104C72E89546E168BD985FAF9A16E5FB1C156D56083B37EF982095299026AB6A1560FBB2BFEFDEBC3D022047F57B793D2EE1FD1DE5F1D2485B9B64474C3E278FE32C68B50CA1A2B3207B5B499AED7AA617C6256C7FC1DAFB9CF277019E30E8DE') & 0xffffffff)
# print(crc32)


# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5
# import binascii
# from Crypto.Cipher import DES3
# from Crypto.Random import get_random_bytes
# from cryptography.hazmat.primitives import serialization
# import os

# e = int('010001', 16)  # exponente publico de la llave
# n = int('B80E225FD13FE34B4F089B01DCF4232B55A488050848B2E81D06BDE6E201FBF6061C6D52B00BC70A32128F45755B2D4D1D3C5799C5D1E00965F892196044078503894F104A8822B1ECFD5C41BCEB03412C894552CB1854317C44205E9133A02D96DF441A0771073E1467A791BA5CB3FA4A7D97099DC4E7EC83B52423F32183B46C6E3083686AC1A4091780EF89FE9A690741141AC5B75D874A965A82B1825A8C4F605043307FF7593186F14A877563934686611F2FA79181443B5398E5271FAEDA35B728C19A49444723C54799A2CB2C272B9926E5DDA0440B3F6267BC3C80BC98C9A3FAEF0E7C21FC0A7CBB2960781D1724B5506C3845D14157E5667B3FA489', 16)
#  # Modulo de la llave publica
# randomkey = get_random_bytes(16)
# key = DES3.adjust_key_parity(randomkey)
# print("E: ", randomkey.hex())

# with open("rsa_public_example.pem") as key_file:
#     publickey = serialization.load_pem_public_key(
#         key_file.read(),
#         password=None,
#     )
    
# add = bytes.fromhex('''00027F14F748E4804EF202B17BA24B3B3A1CCF7A0219913B98DF942EDCF239C367AF93C11B240EC6255924250291564D2C1BAA9CF0ACBB0D1E1988457C9C460CA6EF187AC450BE419417E5AE6EB715469A6B47D156E9F8245435F1AAE885E306A29FF1D8459A1DC42594C378A343C722E8D9254A4CC1ED2C515D64793052D1CA269E0D77A305B2926ECCC89F021748DFE01DA7BDA88D9FB2B2A32E922357DAB98193FAAD426874D42CB47E204A9B09C683963621B9FC7D62A945EEF752AB83E663BC937F08F15AAFC6D766950997C29A2456BB10BC4A703F704DED252E276E44EB52D8122496A4CBCAD3CD023DF82A000123456789ABCDEFFEDCBA9876543210''') 
# #ciphertext = publickey.encrypt(add,padding.)
# # Construct a `RSAobj` with only ( n, e ), thus with only PublicKey

# with open(os.path.expanduser('receiver.pem')) as public_key_file:
#      public_key = RSA.importKey(public_key_file.read())
# pubKey =  RSA.importKey(open("rsa_public_example.pem").read()) #RSA.construct( ( n, e ) )
# #pubKey = rsaKey.publickey()
# print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")

# # Export if needed
# #pubKeyPEM = rsaKey.exportKey()

# #print(pubKeyPEM.decode('ascii'))


# print("KEY PARITY ", key.hex())
# descipher = DES3.new(key,DES3.MODE_ECB)
# checkValue = descipher.encrypt(bytes.fromhex('0000000000000000'))
# print("check value: ", checkValue.hex())

# # Encrypt message using RSA scheme
# msg = bytes.fromhex('''00027F14F748E4804EF202B17BA24B3B3A1CCF7A0219913B98DF942EDCF239C367AF93C11B240EC6255924250291564D2C1BAA9CF0ACBB0D1E1988457C9C460CA6EF187AC450BE419417E5AE6EB715469A6B47D156E9F8245435F1AAE885E306A29FF1D8459A1DC42594C378A343C722E8D9254A4CC1ED2C515D64793052D1CA269E0D77A305B2926ECCC89F021748DFE01DA7BDA88D9FB2B2A32E922357DAB98193FAAD426874D42CB47E204A9B09C683963621B9FC7D62A945EEF752AB83E663BC937F08F15AAFC6D766950997C29A2456BB10BC4A703F704DED252E276E44EB52D8122496A4CBCAD3CD023DF82A000123456789ABCDEFFEDCBA9876543210''')  #randomkey
# print("MSG: ", msg.hex())


# #encryptor = PKCS1_v1_5.new(pubKey)
# encryptor = PKCS1_v1_5.new(pubKey)
# encrypted = encryptor.encrypt(msg)
# print("Encrypted:", encrypted.hex())



# # import os
# # from Crypto.Cipher import PKCS1_v1_5
# # from Crypto.PublicKey import RSA
# # from Crypto.Random import get_random_bytes
# # from Crypto.Hash import SHA
# # from Crypto import Random
# # from Crypto.Cipher import DES3

# # with open(os.path.expanduser('receiver.pem')) as public_key_file:
# #     public_key = RSA.importKey(public_key_file.read())


# # transport_key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210') #get_random_bytes(16) 
# # print("Transport key aleatoria: ", transport_key.hex())

# # descipher = DES3.new(transport_key,DES3.MODE_ECB)
# # msg = descipher.encrypt(bytes.fromhex('0000000000000000'))
# # print("check value: ", msg.hex())

# # cipher = PKCS1_v1_5.new(public_key)

# # print("Cifrando con PKCS1#v1.5")

# # # ciphertext =  bytes.fromhex('''1B249D03A980AA7A964E84A0D7883CA25FFB3957F3AB48C8A7988B934862D9BD
# # # AB01118B7A20EE8FEA4B0E0AD3FB7DD09C14F154425375FC6F5DF1347F523AA0
# # # 8C627CE741CEF83770DB37C69AE1F65BA8084B8B9B3FC8E6545B56F9F35A9860
# # # CD945B78AAC807BDD8BAAB26B16BEE704E2D1D99E3BDC5A056234EF49F78561A
# # # 8A7FB3C47759647CC3874EBBC8DDC1A85BE60FED769EBCDFADCDA9B60436B75B
# # # F87E723DB62552916A6FB2B328368D3D7059973DBD1AF8E24E309FD6DC07684E
# # # 46800B5326D757A7F795807F0229BAC17D127F0FF31D3ABEABA68D0363806107
# # # F7CE4A0B82D63515AEF79BFFEF88D8A28D6457CEC9445F074334683EE03739BB''')
# # ciphertext = cipher.encrypt(transport_key) 
# # print("Transport Key cifrada bajo RSA publica: ", ciphertext.hex())

# # private_key = RSA.importKey(open("private.pem").read())
# # dsize = SHA.digest_size
# # sentinel = Random.new().read(15+dsize)
# # decipher = PKCS1_v1_5.new(private_key)
# # #print("sentinel ", sentinel.hex())
# # decipherText = decipher.decrypt(ciphertext,sentinel)
# # if decipherText == sentinel : 
# #     print("Ocurrio un error al descifrar la llave")
# # else :
# #     print("Descifrado de Transport Key Correcto")
# #     print("Transport Key descifrada: ", decipherText.hex())