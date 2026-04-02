from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_identity():
    # 1. Generate the key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 2. Serialize Private Key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
    )

    # 3. Serialize Public Key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Save to disk
    with open("my_identity_key.pem", "wb") as f:
        f.write(pem_private)
        
    with open("my_identity_public_key.pem", "wb") as f:
        f.write(pem_public)
        
    print("[+] Keys successfully generated and saved!")

if __name__ == "__main__":
    generate_identity()