import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key



class Encryption:
        private_key = None
        public_key = None
        ciphertext = ''
        plaintext = ''

        def generate_keys(self):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend())

            self.public_key = private_key.public_key()
            self.private_key = private_key
            self.save_key(private_key, "privatekey")

        def getPrivateKey(self):
            return self.private_key

        def getPublicKey(self):
            pem_public_key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            # pem = pem_public_key.splitlines()

            with open("publickey", 'wb') as pem_out:
                pem_out.write(pem_public_key)

            return pem_public_key

        def save_key(self, key, filename):
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            with open(filename, 'wb') as pem_out:
                pem_out.write(pem)

        def encrypt(self, key, message):
            # key_file = open("publickey", "rb")
            # data = key_file.read()
            # data.decode('utf-8')
            # print(data)
            # message.encode("utf-8")
            # print(message)
            key = key.encode("utf-8")

            public_key = load_pem_public_key(key, default_backend())

            message = bytes(message, encoding="utf-8")
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None))
            print(ciphertext)
            return ciphertext

        def decrypt(self, key, message):
            with open("privatekey", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            message = private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

            return message

        def generateSymmetricKey(self):
            key = os.urandom(32)
            iv = os.urandom(16)

            return iv, key

        def symmetricEncryption(self, iv, key, message):
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
            encryptor = cipher.encryptor()
            ct = encryptor.update(message) + encryptor.finalize()
            return ct

        def symmetricDecrypt(self, iv, key, msg):
            decryptor = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=default_backend()
            ).decryptor()
            return decryptor.update(msg) + decryptor.finalize()





class Main1():

    encryption = Encryption()
    key1 = encryption.generateSymmetricKey()
    key2 = encryption.generateSymmetricKey()
    key3 = encryption.generateSymmetricKey()

    global onionRoute


    simpleMessage = "Hello!!!!!"
    CMD1 = "MSG"
    CMD2 = "FWD"
    CMD3 = "FWD"
    IP1 = "192.168.0.1"
    IP2 = "192.168.0.2"
    IP3 = "192.168.0.3"

    CMD1 = CMD1.encode('utf-8')
    CMD2 = CMD2.encode('utf-8')
    CMD3 = CMD3.encode('utf-8')



    CMD1 = encryption.symmetricEncryption(key1[0], key1[1], CMD1)
    CMD1 += CMD2
    CMD1 = encryption.symmetricEncryption(key2[0], key2[1], CMD1)
    CMD1 += CMD3
    CMD1 = encryption.symmetricEncryption(key3[0], key3[1], CMD1)


    simpleMessage = simpleMessage.encode('utf-8)')

    onionLayer1 = encryption.symmetricEncryption(key1[0], key1[1], simpleMessage)
    onionLayer2 = encryption.symmetricEncryption(key2[0], key2[1], onionLayer1)
    onionLayer3 = encryption.symmetricEncryption(key3[0], key3[1], onionLayer2)

    dict = {}
    dict['msg'] = onionLayer3
    dict['cmd'] = CMD1

    #Full onion encryption dict, this is what we will send to the first OR
    print(dict)
    onionLayerPeeled3 = encryption.symmetricDecrypt(key3[0], key3[1], dict['msg'])
    onionLayerPeeled2 = encryption.symmetricDecrypt(key2[0], key2[1], onionLayerPeeled3)
    onionLayerPeeled1 = encryption.symmetricDecrypt(key1[0], key1[1], onionLayerPeeled2)

    cmd1 = encryption.symmetricDecrypt(key3[0], key3[1], dict['cmd'])
    #Contains FWD within it but full of garbage characters, padding?
    print(cmd1)
    cmd2 = encryption.symmetricDecrypt(key2[0], key2[1], cmd1)
    #Contains FWD within it but full of garbage characters, issue with byte concatenation?
    print(cmd2)
    cmd3 = encryption.symmetricDecrypt(key1[0], key1[1], cmd2)
    #MSG succeeds! NO string concat involved
    print("success  \n" + onionLayerPeeled1.decode('utf-8'))


    print(cmd3)


def main():
        # display some lines

        if __name__ == "__main__": Encryption()
