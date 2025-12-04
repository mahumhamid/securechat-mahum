"""
Secure Chat Client - connects to server with PKI authentication.
"""

import socket
import json
import os
import secrets
from dotenv import load_dotenv

from app.crypto.pki import load_certificate, load_private_key, validate_certificate_chain, get_certificate_fingerprint, export_certificate_pem
from app.crypto.dh import DHKeyExchange, DEFAULT_P, DEFAULT_G
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_data, verify_signature
from app.storage.transcript import TranscriptManager
from app.common.utils import b64encode, b64decode, sha256_bytes, now_ms
from app.common.protocol import *

load_dotenv()


class SecureChatClient:
    """Secure chat client with PKI authentication."""
    
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5555))
        
        # Load client certificate and private key
        self.client_cert = load_certificate('certs/client_cert.pem')
        self.client_key = load_private_key('certs/client_key.pem')
        self.ca_cert_path = 'certs/ca_cert.pem'
        
        # Session state
        self.server_cert = None
        self.session_key = None
        self.username = None
        self.seqno = 0
        self.server_seqno = 0
        self.transcript = None
        self.sock = None
        
        print("[✓] Client initialized")
    
    def connect(self):
        """Connect to server."""
        print(f"[*] Connecting to {self.host}:{self.port}...")
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print("[✓] Connected to server")
            return True
        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            return False
    
    def start(self):
        """Start client interaction."""
        if not self.connect():
            return
        
        try:
            # Phase 1: Control Plane
            if not self.phase1_control_plane():
                return
            
            # Phase 2: Key Agreement
            if not self.phase2_key_agreement():
                return
            
            # Phase 3: Data Plane
            self.phase3_data_plane()
            
            # Phase 4: Teardown
            self.phase4_teardown()
            
        except Exception as e:
            print(f"[✗] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()
                print("[*] Disconnected from server")
    
    def phase1_control_plane(self) -> bool:
        """Phase 1: Certificate exchange and authentication."""
        print("\n=== PHASE 1: CONTROL PLANE ===")
        
        # Send hello with certificate
        hello = HelloMessage(
            client_cert=export_certificate_pem(self.client_cert).decode('utf-8'),
            nonce=b64encode(secrets.token_bytes(16))
        )
        self.send_message(hello.model_dump_json())
        print("[✓] Hello sent with certificate")
        
        # Receive server hello
        data = self.recv_message()
        server_hello = json.loads(data)
        
        if server_hello['type'] == 'error':
            print(f"[✗] {server_hello['code']}: {server_hello['message']}")
            return False
        
        # Validate server certificate
        server_cert_pem = server_hello['server_cert'].encode('utf-8')
        valid, message, cert = validate_certificate_chain(server_cert_pem, self.ca_cert_path, "server.local")
        
        if not valid:
            print(f"[✗] {message}")
            return False
        
        self.server_cert = cert
        fingerprint = get_certificate_fingerprint(cert)
        print(f"[✓] Server certificate validated (fingerprint: {fingerprint[:16]}...)")
        
        # Receive server DH parameters for control plane
        data = self.recv_message()
        server_dh_params = json.loads(data)
        
        # Perform temporary DH for control plane
        temp_dh = DHKeyExchange(server_dh_params['p'], server_dh_params['g'])
        temp_public = temp_dh.generate_keypair()
        
        # Send client DH
        client_dh = DHClientMessage(g=server_dh_params['g'], p=server_dh_params['p'], A=temp_public)
        self.send_message(client_dh.model_dump_json())
        
        # Compute shared secret for control plane
        temp_dh.compute_shared_secret(server_dh_params['A'])
        control_key = temp_dh.derive_session_key()
        print("[✓] Control plane encryption established")
        
        # Authentication choice
        print("\n" + "="*50)
        print("1. Register new account")
        print("2. Login with existing account")
        print("="*50)
        choice = input("Choose option [1/2]: ").strip()
        
        if choice == '1':
            return self.register(control_key)
        elif choice == '2':
            return self.login(control_key)
        else:
            print("[✗] Invalid choice")
            return False
    
    def register(self, control_key: bytes) -> bool:
        """Register new user."""
        print("\n--- Registration ---")
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # Create registration message
        reg_msg = RegisterMessage(email=email, username=username, password=password)
        
        # Encrypt and send
        encrypted = aes_encrypt(reg_msg.model_dump_json().encode('utf-8'), control_key)
        self.send_message(b64encode(encrypted))
        
        # Receive response
        data = self.recv_message()
        encrypted_resp = b64decode(data)
        decrypted = aes_decrypt(encrypted_resp, control_key)
        response = json.loads(decrypted.decode('utf-8'))
        
        if response['success']:
            self.username = username
            print(f"[✓] {response['message']}")
            return True
        else:
            print(f"[✗] {response['message']}")
            return False
    
    def login(self, control_key: bytes) -> bool:
        """Login existing user."""
        print("\n--- Login ---")
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        
        # Create login message
        login_msg = LoginMessage(email=email, password=password, nonce=b64encode(secrets.token_bytes(16)))
        
        # Encrypt and send
        encrypted = aes_encrypt(login_msg.model_dump_json().encode('utf-8'), control_key)
        self.send_message(b64encode(encrypted))
        
        # Receive response
        data = self.recv_message()
        encrypted_resp = b64decode(data)
        decrypted = aes_decrypt(encrypted_resp, control_key)
        response = json.loads(decrypted.decode('utf-8'))
        
        if response['success']:
            self.username = email.split('@')[0]  # Simple username extraction
            print(f"[✓] {response['message']}")
            return True
        else:
            print(f"[✗] {response['message']}")
            return False
    
    def phase2_key_agreement(self) -> bool:
        """Phase 2: DH key exchange for chat session."""
        print("\n=== PHASE 2: KEY AGREEMENT ===")
        
        # Perform DH
        dh = DHKeyExchange(DEFAULT_P, DEFAULT_G)
        client_public = dh.generate_keypair()
        
        # Send DH parameters
        dh_msg = DHClientMessage(g=DEFAULT_G, p=DEFAULT_P, A=client_public)
        self.send_message(dh_msg.model_dump_json())
        
        # Receive server DH
        data = self.recv_message()
        server_dh = json.loads(data)
        
        # Compute shared secret
        dh.compute_shared_secret(server_dh['B'])
        self.session_key = dh.derive_session_key()
        
        print(f"[✓] Session key established: {self.session_key.hex()[:32]}...")
        
        # Initialize transcript
        server_fingerprint = get_certificate_fingerprint(self.server_cert)
        transcript_file = f"transcripts/client_{self.username}_{now_ms()}.txt"
        self.transcript = TranscriptManager(transcript_file, server_fingerprint)
        print(f"[✓] Transcript initialized: {transcript_file}")
        
        return True
    
    def phase3_data_plane(self):
        """Phase 3: Encrypted message exchange."""
        print("\n=== PHASE 3: DATA PLANE ===")
        print("[*] Chat session active. Type 'quit' to end.\n")
        
        import threading
        
        # Receiver thread
        def receive_messages():
            while True:
                try:
                    data = self.recv_message()
                    if not data:
                        break
                    
                    msg = json.loads(data)
                    
                    if msg['type'] == 'msg':
                        if self.process_incoming_message(msg):
                            # Decrypt and display
                            ct = b64decode(msg['ct'])
                            plaintext = aes_decrypt(ct, self.session_key).decode('utf-8')
                            print(f"\n[Server]: {plaintext}")
                            print("[Client]:", end=" ", flush=True)
                    elif msg['type'] == 'quit':
                        print("\n[*] Server ended session")
                        break
                    elif msg['type'] == 'receipt':
                        # Save server receipt
                        receipt_file = f"transcripts/receipt_server_{now_ms()}.json"
                        with open(receipt_file, 'w') as f:
                            json.dump(msg, f, indent=2)
                        print(f"\n[✓] Server receipt received: {receipt_file}")
                        break
                        
                except Exception as e:
                    print(f"\n[✗] Receive error: {e}")
                    break
        
        recv_thread = threading.Thread(target=receive_messages, daemon=True)
        recv_thread.start()
        
        # Sender loop
        while True:
            try:
                print("[Client]:", end=" ", flush=True)
                message = input()
                
                if message.lower() == 'quit':
                    self.send_message(json.dumps({"type": "quit"}))
                    break
                
                self.send_chat_message(message)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[✗] Send error: {e}")
                break
        
        # Wait a bit for receipt
        recv_thread.join(timeout=2)
    
    def process_incoming_message(self, msg) -> bool:
        """Process and validate incoming message."""
        # Check sequence number (replay protection)
        if msg['seqno'] <= self.server_seqno:
            print(f"\n[✗] REPLAY detected: seqno {msg['seqno']}")
            return False
        
        self.server_seqno = msg['seqno']
        
        # Verify signature
        digest_data = f"{msg['seqno']}|{msg['ts']}|{msg['ct']}".encode('utf-8')
        digest = sha256_bytes(digest_data)
        signature = b64decode(msg['sig'])
        
        if not verify_signature(digest, signature, self.server_cert):
            print(f"\n[✗] SIG_FAIL: Invalid signature on message {msg['seqno']}")
            return False
        
        # Record in transcript
        self.transcript.append_message(msg['seqno'], msg['ts'], msg['ct'], msg['sig'])
        
        return True
    
    def send_chat_message(self, plaintext: str):
        """Send encrypted and signed chat message."""
        self.seqno += 1
        
        # Encrypt
        ct = aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        ct_b64 = b64encode(ct)
        
        # Sign: SHA256(seqno || ts || ct)
        ts = now_ms()
        digest_data = f"{self.seqno}|{ts}|{ct_b64}".encode('utf-8')
        digest = sha256_bytes(digest_data)
        signature = sign_data(digest, self.client_key)
        sig_b64 = b64encode(signature)
        
        # Create message
        msg = ChatMessage(seqno=self.seqno, ts=ts, ct=ct_b64, sig=sig_b64)
        self.send_message(msg.model_dump_json())
        
        # Record in transcript
        self.transcript.append_message(self.seqno, ts, ct_b64, sig_b64)
    
    def phase4_teardown(self):
        """Phase 4: Generate and exchange session receipts."""
        print("\n=== PHASE 4: TEARDOWN (NON-REPUDIATION) ===")
        
        if not self.transcript:
            return
        
        # Compute transcript hash
        transcript_hash = self.transcript.compute_transcript_hash()
        print(f"[*] Transcript hash: {transcript_hash}")
        
        # Sign transcript hash
        signature = sign_data(transcript_hash.encode('utf-8'), self.client_key)
        sig_b64 = b64encode(signature)
        
        # Create receipt
        receipt = self.transcript.export_receipt(sig_b64, "client")
        
        # Save receipt
        receipt_file = f"transcripts/receipt_client_{self.username}_{now_ms()}.json"
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] Session receipt saved: {receipt_file}")
    
    def send_message(self, data: str):
        """Send length-prefixed message."""
        msg_bytes = data.encode('utf-8')
        length = len(msg_bytes).to_bytes(4, 'big')
        self.sock.sendall(length + msg_bytes)
    
    def recv_message(self) -> str:
        """Receive length-prefixed message."""
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(min(length - len(data), 4096))
            if not chunk:
                return None
            data += chunk
        
        return data.decode('utf-8')


if __name__ == "__main__":
    client = SecureChatClient()
    client.start()