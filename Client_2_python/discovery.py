import socket
import time
import os
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib

SERVICE_TYPE = "_cisc468p2p._tcp.local."

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def load_keys():
    """Loads your private key and all trusted peer public keys."""
    try:
        with open("my_identity_key.pem", "rb") as f:
            my_priv_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("[-] Error: my_identity_key.pem not found.")
        return None, None

    trusted_peers = {}
    os.makedirs("trusted_peers", exist_ok=True)
    
    for filename in os.listdir("trusted_peers"):
        if filename.endswith(".pem"):
            with open(os.path.join("trusted_peers", filename), "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
                trusted_peers[filename] = pub_key
                
    print(f"[*] Loaded {len(trusted_peers)} trusted peers.")
    return my_priv_key, trusted_peers

def start_raw_server(listen_ip, listen_port, my_priv_key, trusted_peers):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        sock.listen(1)
        print(f"[*] Listening on {listen_ip}:{listen_port}...")
        
        conn, addr = sock.accept()
        with conn:
            print(f"[+] Connected to {addr}")
            execute_handshake(conn, my_priv_key, trusted_peers)

def connect_to_peer_raw(peer_ip, peer_port, my_priv_key, trusted_peers):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[*] Connecting to {peer_ip}:{peer_port}...")
        sock.connect((peer_ip, peer_port))
        print(f"[+] Connected to {peer_ip}")
        execute_handshake(sock, my_priv_key, trusted_peers)


def execute_handshake(sock, my_identity_private_key, trusted_peers):
    # 1. Prepare keys
    my_id_pub_bytes = my_identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = ephemeral_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    # 2. Sign and send (128 bytes total)
    signature = my_identity_private_key.sign(eph_pub_bytes)
    sock.sendall(my_id_pub_bytes + eph_pub_bytes + signature)
    
    # 3. Receive peer data
    peer_data = sock.recv(128)
    if len(peer_data) != 128:
        print("[-] Handshake failed: Invalid data length")
        sock.close()
        return
        
    peer_id_bytes = peer_data[:32]
    peer_eph_bytes = peer_data[32:64]
    peer_signature = peer_data[64:]
    
    peer_id_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_id_bytes)
    
    # 4. Verify Identity
    authenticated_peer = None
    for name, pub_key in trusted_peers.items():
        if pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw) == peer_id_bytes:
            try:
                pub_key.verify(peer_signature, peer_eph_bytes)
                authenticated_peer = name
                break
            except Exception:
                pass

    # 5. TOFU Logic
    if not authenticated_peer:
        fingerprint = hashlib.sha256(peer_id_bytes).hexdigest()[:12]
        trust = input(f"\n[?] Unknown peer detected (Fingerprint: {fingerprint}). Trust on first use? (y/n): ")
        
        if trust.strip().lower() == 'y':
            try:
                peer_id_pub_key.verify(peer_signature, peer_eph_bytes)
                filename = f"peer_{fingerprint}.pem"
                filepath = os.path.join("trusted_peers", filename)
                
                with open(filepath, "wb") as f:
                    f.write(peer_id_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
                
                trusted_peers[filename] = peer_id_pub_key
                authenticated_peer = filename
                print(f"[+] Saved new peer to {filepath}")
            except Exception:
                print("[-] Invalid signature from unknown peer. Connection dropped.")
                sock.close()
                return
        else:
            print("[-] Connection rejected by user.")
            sock.close()
            return

    print(f"[+] Peer authenticated as: {authenticated_peer}")

    # 6. Derive Session Key
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_eph_bytes)
    shared_secret = ephemeral_private_key.exchange(peer_public_key)
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cisc468-p2p-file-transfer")
    session_key = hkdf.derive(shared_secret)
    
    print(f"[+] Session Key: {session_key.hex()[:10]}...")

class PeerListener:
    def __init__(self, own_name, listen_port, my_priv_key, trusted_peers):
        self.own_name = own_name
        self.local_ip = get_local_ip()
        self.listen_port = listen_port
        self.my_priv_key = my_priv_key
        self.trusted_peers = trusted_peers

    def remove_service(self, zeroconf, type_, name):
        if name != self.own_name:
            print(f"[-] Peer disconnected: {name}")

    def add_service(self, zeroconf, type_, name):
        if name == self.own_name:
            return
            
        info = zeroconf.get_service_info(type_, name)
        if info:
            peer_ip = socket.inet_ntoa(info.addresses[0])
            peer_port = info.port
            print(f"[+] Peer discovered: {peer_ip}:{peer_port}")
            
            if self.local_ip > peer_ip:
                print("[*] I am the Server. Starting listener...")
                threading.Thread(target=start_raw_server, args=(self.local_ip, self.listen_port, self.my_priv_key, self.trusted_peers)).start()
            else:
                print("[*] I am the Client. Connecting to peer...")
                time.sleep(1) 
                threading.Thread(target=connect_to_peer_raw, args=(peer_ip, peer_port, self.my_priv_key, self.trusted_peers)).start()

    def update_service(self, zeroconf, type_, name):
        pass

def main():
    my_priv_key, trusted_peers = load_keys()
    if my_priv_key is None:
        return

    local_ip = get_local_ip()
    listen_port = 5000  
    node_name = f"PythonClient-{local_ip.replace('.', '-')}.{SERVICE_TYPE}"

    print(f"Starting P2P Node on {local_ip}:{listen_port}...")

    zc = Zeroconf()

    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=node_name,
        addresses=[socket.inet_aton(local_ip)],
        port=listen_port,
        properties={'version': '1.0', 'lang': 'python'},
        server=f"{local_ip.replace('.', '-')}.local." 
    )

    print(f"Advertising service: {node_name}")
    zc.register_service(info)

    listener = PeerListener(own_name=node_name, listen_port=listen_port, my_priv_key=my_priv_key, trusted_peers=trusted_peers) 
    browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

    try:
        print("Listening for peers... (Press Ctrl+C to exit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down node...")
    finally:
        zc.unregister_service(info)
        zc.close()
        print("Offline.")

if __name__ == "__main__":
    main()
