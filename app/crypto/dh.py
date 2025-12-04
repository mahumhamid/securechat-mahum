"""
Classic Diffie-Hellman key exchange with SHA-256 key derivation.
"""

import os
import secrets
import hashlib
from typing import Tuple


# Safe prime parameters (2048-bit MODP group from RFC 3526)
DEFAULT_P = int(os.getenv('DH_P', '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'), 16)
DEFAULT_G = int(os.getenv('DH_G', '2'))


class DHKeyExchange:
    """Handles Diffie-Hellman key exchange and derivation."""
    
    def __init__(self, p: int = DEFAULT_P, g: int = DEFAULT_G):
        """
        Initialize DH parameters.
        
        Args:
            p: Large prime modulus
            g: Generator
        """
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.session_key = None
    
    def generate_keypair(self) -> int:
        """
        Generate private key and compute public key.
        
        Returns:
            public_key: A = g^a mod p
        """
        # Generate random private key (256 bits)
        self.private_key = secrets.randbits(256)
        
        # Compute public key: A = g^a mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        return self.public_key
    
    def compute_shared_secret(self, peer_public_key: int) -> bytes:
        """
        Compute shared secret from peer's public key.
        
        Args:
            peer_public_key: B = g^b mod p (from peer)
        
        Returns:
            shared_secret: K_s = B^a mod p
        """
        if self.private_key is None:
            raise ValueError("Private key not generated. Call generate_keypair() first.")
        
        # Compute shared secret: K_s = B^a mod p
        shared_secret_int = pow(peer_public_key, self.private_key, self.p)
        
        # Convert to bytes (big-endian)
        byte_length = (shared_secret_int.bit_length() + 7) // 8
        self.shared_secret = shared_secret_int.to_bytes(byte_length, byteorder='big')
        
        return self.shared_secret
    
    def derive_session_key(self) -> bytes:
        """
        Derive 16-byte AES-128 session key from shared secret.
        K = Trunc_16(SHA256(K_s))
        
        Returns:
            session_key: 16-byte AES key
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret not computed. Call compute_shared_secret() first.")
        
        # Compute SHA-256 hash of shared secret
        hash_digest = hashlib.sha256(self.shared_secret).digest()
        
        # Truncate to 16 bytes for AES-128
        self.session_key = hash_digest[:16]
        
        return self.session_key
    
    def get_parameters(self) -> Tuple[int, int]:
        """Get DH parameters (p, g)."""
        return self.p, self.g


def perform_dh_exchange_client(peer_public_key: int, p: int, g: int) -> Tuple[int, bytes]:
    """
    Client-side DH exchange.
    
    Args:
        peer_public_key: Server's public key B
        p: Prime modulus
        g: Generator
    
    Returns:
        (client_public_key: int, session_key: bytes)
    """
    dh = DHKeyExchange(p, g)
    client_public = dh.generate_keypair()
    dh.compute_shared_secret(peer_public_key)
    session_key = dh.derive_session_key()
    
    return client_public, session_key


def perform_dh_exchange_server(peer_public_key: int, p: int, g: int) -> Tuple[int, bytes]:
    """
    Server-side DH exchange.
    Args:
        peer_public_key: Client's public key A
        p: Prime modulus
        g: Generator
    
    Returns:
        (server_public_key: int, session_key: bytes)
    """
    dh = DHKeyExchange(p, g)
    server_public = dh.generate_keypair()
    dh.compute_shared_secret(peer_public_key)
    session_key = dh.derive_session_key()
    
    return server_public, session_key


# Utility functions
def int_to_bytes(n: int) -> bytes:
    """Convert integer to big-endian bytes."""
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, byteorder='big')