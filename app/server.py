"""
Secure Chat Server - handles authentication, key exchange, and encrypted messaging.
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
from app.storage.db import UserDatabase
from app.storage.transcript import TranscriptManager
from app.common.utils import b64encode, b64decode, sha256_bytes, now_ms
from app.common.protocol import *

load_dotenv()


class SecureChatServer:
    """Secure chat server with PKI authentication."""
    
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5555))
        
        # Load server certificate and private key
        self.server_cert = load_certificate('certs/server_cert.pem')
        self.server_key = load_private_key('certs/server_key.pem')
        self.ca_cert_path = 'certs/ca_cert.pem'
        
        # Database
        self.db = UserDatabase()
        self.db.connect()
        
        # Session state
        self.client_cert = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = None
        
        print(f"[✓] Server initialized on {self.host}:{self.port}")
    
    def start(self):
        """Start the server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for client connection...")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                print(f"\n[✓] Client connected from {address}")
                
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"[✗] Error handling client: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    client_socket.close()
                    print("[*] Client disconnected")
                    
                    # Reset session state
                    self.reset_session()
                    print("\n[*] Waiting for next client...")
                    
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        finally:
            server_socket.close()
            self.db.disconnect()
    
    def reset_session(self):
        """Reset session state."""
        self.client_cert = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = None
    
    def handle_client(self, sock):
        """Handle client connection through all protocol phases."""
        
        # Phase 1: Control Plane (Certificate Exchange & Authentication)
        if not self.phase1_control_plane(sock):
            return
        
        # Phase 2: Key Agreement (DH for chat session)
        if not self.phase2_key_agreement(sock):
            return
        
        # Phase 3: Data Plane (Encrypted Chat)
        self.phase3_data_plane(sock)
        
        # Phase 4: Teardown (Non-Repudiation)
        self.phase4_teardown(sock)
    
    def phase1_control_plane(self, sock) -> bool:
        """Phase 1: Certificate exchange and authentication."""
        print("\n=== PHASE 1: CONTROL PLANE ===")
        
        # Receive client hello
        data = self.recv_message(sock)
        if not data:
            return False
        
        msg = json.loads(data)
        if msg['type'] != 'hello':
            self.send_error(sock, "PROTO_ERROR", "Expected hello message")
            return False
        
        # Validate client certificate
        client_cert_pem = msg['client_cert'].encode('utf-8')
        valid, message, cert = validate_certificate_chain(client_cert_pem, self.ca_cert_path)
        
        if not valid:
            print(f"[✗] {message}")
            self.send_error(sock, "BAD_CERT", message)
            return False
        
        self.client_cert = cert
        fingerprint = get_certificate_fingerprint(cert)
        print(f"[✓] Client certificate validated (fingerprint: {fingerprint[:16]}...)")
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=export_certificate_pem(self.server_cert).decode('utf-8'),
            nonce=b64encode(secrets.token_bytes(16))
        )
        self.send_message(sock, server_hello.model_dump_json())
        print("[✓] Server hello sent")
        
        # Perform temporary DH for control plane encryption
        temp_dh = DHKeyExchange(DEFAULT_P, DEFAULT_G)
        temp_public = temp_dh.generate_keypair()
        
        # Send DH parameters
        dh_msg = DHClientMessage(g=DEFAULT_G, p=DEFAULT_P, A=temp_public)
        self.send_message(sock, dh_msg.model_dump_json())
        
        # Receive client DH
        data = self.recv_message(sock)
        client_dh = json.loads(data)
        
        # Compute shared secret for control plane
        temp_dh.compute_shared_secret(client_dh['A'])
        control_key = temp_dh.derive_session_key()
        print("[✓] Control plane encryption established")
        
        # Receive encrypted registration/login
        data = self.recv_message(sock)
        encrypted_data = b64decode(data)
        decrypted = aes_decrypt(encrypted_data, control_key)
        auth_msg = json.loads(decrypted.decode('utf-8'))
        
        if auth_msg['type'] == 'register':
            return self.handle_registration(sock, auth_msg, control_key)
        elif auth_msg['type'] == 'login':
            return self.handle_login(sock, auth_msg, control_key)
        else:
            self.send_error(sock, "PROTO_ERROR", "Expected register or login")
            return False
    
    def handle_registration(self, sock, msg, control_key) -> bool:
        """Handle user registration."""
        print(f"[*] Registration request: {msg['email']}")
        
        success, message = self.db.register_user(msg['email'], msg['username'], msg['password'])
        
        response = ResponseMessage(success=success, message=message)
        encrypted_response = aes_encrypt(response.model_dump_json().encode('utf-8'), control_key)
        self.send_message(sock, b64encode(encrypted_response))
        
        if success:
            self.authenticated_user = msg['username']
            print(f"[✓] User registered and authenticated: {self.authenticated_user}")
            return True
        else:
            print(f"[✗] Registration failed: {message}")
            return False
    
    def handle_login(self, sock, msg, control_key) -> bool:
        """Handle user login."""
        print(f"[*] Login attempt: {msg['email']}")
        
        success, username = self.db.authenticate_user(msg['email'], msg['password'])
        
        if success:
            self.authenticated_user = username
            response = ResponseMessage(success=True, message=f"Welcome back, {username}!")
        else:
            response = ResponseMessage(success=False, message="Authentication failed")
        
        encrypted_response = aes_encrypt(response.model_dump_json().encode('utf-8'), control_key)
        self.send_message(sock, b64encode(encrypted_response))
        
        if success:
            print(f"[✓] User authenticated: {self.authenticated_user}")
            return True
        else:
            print(f"[✗] Authentication failed")
            return False
    
    def phase2_key_agreement(self, sock) -> bool:
        """Phase 2: DH key exchange for chat session."""
        print("\n=== PHASE 2: KEY AGREEMENT ===")
        
        # Receive client DH parameters
        data = self.recv_message(sock)
        client_dh = json.loads(data)
        
        if client_dh['type'] != 'dh_client':
            return False
        
        # Perform DH
        dh = DHKeyExchange(client_dh['p'], client_dh['g'])
        server_public = dh.generate_keypair()
        dh.compute_shared_secret(client_dh['A'])
        self.session_key = dh.derive_session_key()
        
        print(f"[✓] Session key established: {self.session_key.hex()[:32]}...")
        
        # Send server DH response
        dh_response = DHServerMessage(B=server_public)
        self.send_message(sock, dh_response.model_dump_json())
        
        # Initialize transcript
        client_fingerprint = get_certificate_fingerprint(self.client_cert)
        transcript_file = f"transcripts/server_{self.authenticated_user}_{now_ms()}.txt"
        self.transcript = TranscriptManager(transcript_file, client_fingerprint)
        print(f"[✓] Transcript initialized: {transcript_file}")
        
        return True
    
    def phase3_data_plane(self, sock):
        """Phase 3: Encrypted message exchange."""
        print("\n=== PHASE 3: DATA PLANE ===")
        print("[*] Chat session active. Type 'quit' to end.\n")
        
        import threading
        
        # Receiver thread
        def receive_messages():
            while True:
                try:
                    data = self.recv_message(sock)
                    if not data:
                        break
                    
                    msg = json.loads(data)
                    
                    if msg['type'] == 'msg':
                        if self.process_incoming_message(msg):
                            # Decrypt and display
                            ct = b64decode(msg['ct'])
                            plaintext = aes_decrypt(ct, self.session_key).decode('utf-8')
                            print(f"\n[Client]: {plaintext}")
                            print("[Server]:", end=" ", flush=True)
                    elif msg['type'] == 'quit':
                        print("\n[*] Client ended session")
                        break
                        
                except Exception as e:
                    print(f"\n[✗] Receive error: {e}")
                    break
        
        recv_thread = threading.Thread(target=receive_messages, daemon=True)
        recv_thread.start()
        
        # Sender loop
        while True:
            try:
                print("[Server]:", end=" ", flush=True)
                message = input()
                
                if message.lower() == 'quit':
                    self.send_message(sock, json.dumps({"type": "quit"}))
                    break
                
                self.send_chat_message(sock, message)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[✗] Send error: {e}")
                break
    
    def process_incoming_message(self, msg) -> bool:
        """Process and validate incoming message."""
        # Check sequence number (replay protection)
        if msg['seqno'] <= self.client_seqno:
            print(f"\n[✗] REPLAY detected: seqno {msg['seqno']}")
            return False
        
        self.client_seqno = msg['seqno']
        
        # Verify signature
        digest_data = f"{msg['seqno']}|{msg['ts']}|{msg['ct']}".encode('utf-8')
        digest = sha256_bytes(digest_data)
        signature = b64decode(msg['sig'])
        
        if not verify_signature(digest, signature, self.client_cert):
            print(f"\n[✗] SIG_FAIL: Invalid signature on message {msg['seqno']}")
            return False
        
        # Record in transcript
        self.transcript.append_message(msg['seqno'], msg['ts'], msg['ct'], msg['sig'])
        
        return True
    
    def send_chat_message(self, sock, plaintext: str):
        """Send encrypted and signed chat message."""
        self.seqno += 1
        
        # Encrypt
        ct = aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        ct_b64 = b64encode(ct)
        
        # Sign: SHA256(seqno || ts || ct)
        ts = now_ms()
        digest_data = f"{self.seqno}|{ts}|{ct_b64}".encode('utf-8')
        digest = sha256_bytes(digest_data)
        signature = sign_data(digest, self.server_key)
        sig_b64 = b64encode(signature)
        
        # Create message
        msg = ChatMessage(seqno=self.seqno, ts=ts, ct=ct_b64, sig=sig_b64)
        self.send_message(sock, msg.model_dump_json())
        
        # Record in transcript
        self.transcript.append_message(self.seqno, ts, ct_b64, sig_b64)
    
    def phase4_teardown(self, sock):
        """Phase 4: Generate and exchange session receipts."""
        print("\n=== PHASE 4: TEARDOWN (NON-REPUDIATION) ===")
        
        if not self.transcript:
            return
        
        # Compute transcript hash
        transcript_hash = self.transcript.compute_transcript_hash()
        print(f"[*] Transcript hash: {transcript_hash}")
        
        # Sign transcript hash
        signature = sign_data(transcript_hash.encode('utf-8'), self.server_key)
        sig_b64 = b64encode(signature)
        
        # Create receipt
        receipt = self.transcript.export_receipt(sig_b64, "server")
        
        # Save receipt
        receipt_file = f"transcripts/receipt_server_{self.authenticated_user}_{now_ms()}.json"
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] Session receipt saved: {receipt_file}")
        
        # Send receipt to client
        try:
            self.send_message(sock, json.dumps(receipt))
            print("[✓] Receipt sent to client")
        except:
            print("[!] Could not send receipt (client disconnected)")
    
    def send_message(self, sock, data: str):
        """Send length-prefixed message."""
        msg_bytes = data.encode('utf-8')
        length = len(msg_bytes).to_bytes(4, 'big')
        sock.sendall(length + msg_bytes)
    
    def recv_message(self, sock) -> str:
        """Receive length-prefixed message."""
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 4096))
            if not chunk:
                return None
            data += chunk
        
        return data.decode('utf-8')
    
    def send_error(self, sock, code: str, message: str):
        """Send error message."""
        error = ErrorMessage(code=code, message=message)
        self.send_message(sock, error.model_dump_json())


if __name__ == "__main__":
    server = SecureChatServer()
    server.start()