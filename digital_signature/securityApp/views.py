from django.shortcuts import render
import rsa
import base64

class Signature :
    def __init__(self, signDate="", signTime="", privateKeyFile="/django2/myapp/keys/server/private.pem", publicKeyFile="/django2/myapp/keys/server/public.pem") :
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