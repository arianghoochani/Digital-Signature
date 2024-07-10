from rest_framework.response import Response
from rest_framework.decorators import api_view

import rsa
import base64

class Signature :
    def __init__(self, signDate="", signTime="", privateKeyFile=r"D:\arian\repos\Digital-Signature\digital_signature\server\private.pem", publicKeyFile=r"D:\arian\repos\Digital-Signature\digital_signature\server\public.pem") :
        self.signDate = signDate
        self.signTime = signTime
        self.privateKeyFile = privateKeyFile
        self.publicKeyFile = publicKeyFile

    def sign(self, stringToSign) :
        privkey = rsa.PrivateKey.load_pkcs1(open(self.privateKeyFile).read())
        signedMsg = base64.b64encode(rsa.sign(stringToSign.encode(), privkey, 'SHA-1'))
        signedString = (signedMsg).decode()
        self.signedString = signedString
        return signedString

    def verify(self, msg, signature) :
        try:
            public_key = rsa.PublicKey.load_pkcs1_openssl_pem(open(self.publicKeyFile).read())
            signature_bytes = base64.b64decode(signature)      
            rsa.verify(msg.encode("utf-8"), signature_bytes, public_key)
            return True
        except:
            return False




@api_view(["GET"])
def sign(request):
    # Generate RSA keys with a key size of 2048 bits
    (public_key, private_key) = rsa.newkeys(2048)
    with open(r"D:\arian\repos\Digital-Signature\digital_signature\server\public.pem", "rb") as public_key_file:
        pem_public_key = public_key_file.read()
    # Example string to sign
    string_to_sign = "sdasdasdasd"

    # Sign the string using the private key
    signature = rsa.sign(string_to_sign.encode(), private_key, 'SHA-256')

    # Serialize the public key to PEM format
    pem_public_key = public_key.save_pkcs1().decode('utf-8')

    # Prepare the response
    response_data = {
        'public_key': pem_public_key,
        'signature': signature.hex()  # Convert signature to hex string for easy display
    }

    return Response(response_data)