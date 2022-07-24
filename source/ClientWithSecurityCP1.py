import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # obtain the cert of the certifying authority
    f = open("auth/cacsertificate.crt", "rb")
    ca_cert_raw = f.read()
    f.close()
    ca_cert = x509.load_pem_x509_certificate(
        data=ca_cert_raw, backend=default_backend()
    )

    ca_public_key = ca_cert.public_key()
    
    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected\n")

        while True:
            # authenticate first before proceeding with FTP

            # hash the auth_message before sending it
            auth_message = hashes.Hash(hashes.SHA256())
            # create a random message each time to prevent 
            # replay attacks if the attacker knows the auth message
            nonce = secrets.token_bytes(32) # 256 bit nonce
            # hash the auth message to further protect it
            # in case the 
            auth_message.update(nonce)
            auth_message = auth_message.finalize()

            auth_message_size = len(auth_message)
            s.sendall(convert_int_to_bytes(3))
            s.sendall(convert_int_to_bytes(auth_message_size))
            s.sendall(auth_message)
            signed_auth_msg_length = s.recv(8)
            signed_auth_msg = s.recv(convert_bytes_to_int(signed_auth_msg_length))
            signed_cert_length = s.recv(8)
            signed_cert = s.recv(convert_bytes_to_int(signed_cert_length))

            # parse the cert received
            server_cert = x509.load_pem_x509_certificate(
                data=signed_cert, backend=default_backend()
            )

            # verify if the signed cert from server is authentic
            ca_public_key.verify(
                signature=server_cert.signature, # signature bytes to  verify
                data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                algorithm=server_cert.signature_hash_algorithm,
            )
            
            # check if the server_cert is valid
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after

            # obtain the server cert's public key
            public_key = server_cert.public_key()

            # check that the server signed the message
            # signed_auth_msg should be == auth_message when decrypted with the public key
            public_key.verify(
                signed_auth_msg,
                auth_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Authenticated\n")

            filename = input("Enter a filename to send (enter -1 to exit):")
            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:")
            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                ciphertext = b""

                # max 62 bytes of data can be encrypted at once
                data = fp.read(62)

                while data:
                # encrypt the data with server's public key before sending
                # server will decrypt the data with its private key
                    partial_ciphertext = public_key.encrypt(
                        data,
                        # using OEAP padding since it is the more secure one
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # append the partial_ciphertext to ciphertext
                    ciphertext+=partial_ciphertext
                    data = fp.read(62)

                print(ciphertext)
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(ciphertext)))
                s.sendall(ciphertext)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
