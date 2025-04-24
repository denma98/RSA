import time
from custom_rsa import generate_keypair, encrypt, decrypt, sign, verify_signature, RSAKey

key_size = 1024

class CertificationAuthority:
    def __init__(self):
        self.public_key, self.private_key = generate_keypair("CA", key_size)
        self.id = "CA_001"
        self.client_public_keys = {}
        
    def register_client(self, client_id, public_key):
        self.client_public_keys[client_id] = public_key
        
    def create_certificate(self, client_id):
        if client_id not in self.client_public_keys:
            raise ValueError(f"Client {client_id} not registered")
            
        cert_data = f"{client_id}|{self.client_public_keys[client_id].n}|{self.client_public_keys[client_id].e}|{int(time.time())}|3600|{self.id}"
        signature = sign(cert_data, self.private_key)
        
        complete_cert = f"{cert_data}||{signature}"
        
        return complete_cert

class Client:
    def __init__(self, client_id, ca_public_key):
        self.public_key, self.private_key = generate_keypair(client_id, key_size)
        self.id = client_id
        self.ca_public_key = ca_public_key
        self.known_certificates = {}
        
    def request_certificate(self, ca):
        return ca.create_certificate(self.id)
        
    def verify_certificate(self, certificate):
        try:
            cert_data, signature = certificate.split("||")
            signature = int(signature)
            
            if verify_signature(cert_data, signature, self.ca_public_key):
                client_id, pub_key_n, pub_key_e, timestamp, duration, ca_id = cert_data.split("|")
                return {
                    "id": client_id,
                    "public_key": {
                        "n": int(pub_key_n),
                        "e": int(pub_key_e)
                    },
                    "timestamp": int(timestamp),
                    "duration": int(duration),
                    "ca_id": ca_id
                }
            return None
        except:
            return None
            
    def encrypt_message(self, message, recipient_public_key):
        encrypted = encrypt(message, recipient_public_key)
        return str(encrypted)
        
    def decrypt_message(self, encrypted_message):
        try:
            ciphertext = int(encrypted_message)
            return decrypt(ciphertext, self.private_key)
        except:
            return None

def main():
    ca = CertificationAuthority()
    
    client_a = Client("ClientA", ca.public_key)
    client_b = Client("ClientB", ca.public_key)
    
    ca.register_client(client_a.id, client_a.public_key)
    ca.register_client(client_b.id, client_b.public_key)
    
    cert_a = client_a.request_certificate(ca)
    cert_b = client_b.request_certificate(ca)
    
    verified_cert_a = client_b.verify_certificate(cert_a)
    verified_cert_b = client_a.verify_certificate(cert_b)
    
    if verified_cert_a["id"] == client_a.id and verified_cert_b["id"] == client_b.id:
        print("Certificate verification successful!")
        # Reconstruct public keys from certificate data
        client_b_pubkey = RSAKey(verified_cert_b["public_key"]["n"], verified_cert_b["public_key"]["e"])
        client_a_pubkey = RSAKey(verified_cert_a["public_key"]["n"], verified_cert_a["public_key"]["e"])
        
        # Client A sends messages to Client B
        messages = ["Hello1", "Hello2", "Hello3"]
        for msg in messages:
            # A encrypts message for B
            encrypted_msg = client_a.encrypt_message(msg, client_b_pubkey)
            print(f"\nClient A sends: {msg}")
            
            # B decrypts message
            decrypted_msg = client_b.decrypt_message(encrypted_msg)
            if decrypted_msg == msg:
                print(f"Client B receives: {decrypted_msg}")
                # B sends acknowledgment
                ack = f"ACK for {msg}"
                encrypted_ack = client_b.encrypt_message(ack, client_a_pubkey)
                print(f"Client B sends: {ack}")
            
                decrypted_ack = client_a.decrypt_message(encrypted_ack)
                
                if decrypted_ack == ack:
                    print(f"Client A receives: {decrypted_ack}")
                else:
                    print(f"Client A receives: {decrypted_ack} (expected: {ack})")
                    break
            else:
                print(f"Client B receives: {decrypted_msg} (expected: {msg})")
                break
            
    else:
        print("Certificate verification failed!")

if __name__ == "__main__":
    main() 