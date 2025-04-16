# Enhanced Payload Delivery (AES + Chunking + Timing)

## ⚠️ Security Warning & Disclaimer ⚠️

This project demonstrates techniques for obfuscating and transmitting payloads over a network, primarily **for educational purposes within secure, isolated laboratory environments**.

* **EXTREME RISK:** The receiver script contains commented-out code to **execute** the received payload. Executing arbitrary code received over a network is **inherently dangerous** and can lead to complete system compromise. **NEVER** run this on production systems or any machine you care about. Only enable execution in a disposable VM lab setup where you fully understand the risks.
* **INSECURE KEY:** The AES encryption key is **hardcoded** in both scripts. This is **highly insecure** for any real-world application. Secure key management is a complex topic not covered here.
* **EVASION IS NOT GUARANTEED:** While AES encryption, chunking, and timing delays hinder basic signature-based detection and plain-text inspection, they are **NOT** sufficient to bypass modern, sophisticated security systems (NGFW, EDR, Advanced IPS, Behavioral Analysis). Encrypted traffic on non-standard ports, traffic volume, connection patterns, and endpoint behavior can still trigger alerts.
* **ETHICAL USE ONLY:** Use these scripts responsibly and ethically. Unauthorized access to or disruption of computer systems is illegal.

## Description

This project provides a sender and receiver script in Python that demonstrates:

1.  **Payload Encryption:** Using AES-GCM for strong authenticated encryption of the payload, hiding its content from casual inspection and ensuring integrity.
2.  **Data Chunking:** Transmitting the encrypted payload in smaller, fixed-size chunks.
3.  **Length Prefixing:** Sending the size of each chunk before the chunk itself, allowing the receiver to reassemble the data correctly.
4.  **Variable Timing:** Introducing random delays between sending chunks to make the network traffic less uniform and predictable.

The goal is to show methods that can make simple payload delivery slightly harder to detect compared to sending plain text or easily reversible encodings like Base64.

## Features

* **AES-GCM Encryption:** Strong, authenticated encryption (requires `pycryptodome`).
* **Configurable Chunking:** Send data in manageable blocks (`CHUNK_SIZE`).
* **Length Header:** Reliable reassembly using `struct` for packing/unpacking chunk lengths.
* **Randomized Delays:** Variable timing between chunks (`MIN_DELAY`, `MAX_DELAY`).
* **Sender Script (`evasive_payload_sender.py`):** Encrypts and sends the payload.
* **Receiver Script (`evasive_payload_receiver.py`):** Listens, receives, reassembles, decrypts, and (optionally, **DANGEROUSLY**) executes the payload.

## Requirements

* **Python 3:** Scripts are written for Python 3.x.
* **PyCryptodome:** Required for AES encryption. Install on both sender and receiver:
    ```bash
    pip install pycryptodome
    ```
* **Two Machines:** A sender (e.g., Kali Linux) and a receiver (e.g., a target VM) in a networked lab environment.

## Setup

1.  **Install PyCryptodome:** Run `pip install pycryptodome` on both machines.
2.  **Configure Scripts:**
    * Open `evasive_payload_sender.py` and `evasive_payload_receiver.py`.
    * **Crucially, ensure the `AES_KEY` variable is identical in both scripts.** Remember this is insecure for real use.
    * In `evasive_payload_sender.py`, set `TARGET_IP` to the IP address of the receiver machine.
    * In `evasive_payload_receiver.py`, ensure `LISTEN_IP` is correct (usually `0.0.0.0` to listen on all interfaces, or the specific IP of the receiver machine).
    * Ensure `TARGET_PORT` in the sender matches `LISTEN_PORT` in the receiver.
    * Adjust `CHUNK_SIZE`, `MIN_DELAY`, `MAX_DELAY` if desired.
3.  **Payload:** Modify the `payload` variable in `evasive_payload_sender.py` to the command or data you wish to send (use harmless commands for testing).

## Usage

1.  **Start the Receiver:** On the receiver machine (Victim1), run:
    ```bash
    python3 evasive_payload_receiver.py
    ```
    It will start listening for incoming connections.

2.  **Run the Sender:** On the sender machine (Kali), run:
    ```bash
    python3 evasive_payload_sender.py
    ```
    It will encrypt the payload, connect to the receiver, and send the data in timed chunks.

3.  **Observe Output:** Both scripts will print status messages. The receiver will print the decrypted payload if successful. If you uncommented the execution line in the receiver (**highly discouraged**), it will attempt to run the command.

## How It Works

1.  **Sender:**
    * Takes the plain-text `payload`.
    * Generates a unique `nonce` for AES-GCM mode.
    * Encrypts the payload using the shared `AES_KEY` and the `nonce`. This produces `ciphertext` and an authentication `tag`.
    * Concatenates `nonce + tag + ciphertext`.
    * Connects to the receiver via TCP.
    * Iteratively breaks the combined encrypted data into chunks (`CHUNK_SIZE`).
    * For each chunk:
        * Pauses for a random `delay`.
        * Packs the `chunk` length into a fixed-size header (`struct.pack`).
        * Sends the length header.
        * Sends the `chunk` data.
    * Closes the connection when done.

2.  **Receiver:**
    * Listens for an incoming TCP connection.
    * Upon connection, enters a loop to receive data:
        * Reads the fixed-size length header.
        * Unpacks the header (`struct.unpack`) to get the expected `chunk_len`.
        * Reads exactly `chunk_len` bytes from the socket, handling potential partial reads.
        * Appends the received chunk to a buffer (`bytearray`).
        * Repeats until the sender closes the connection (indicated by `recv` returning empty bytes when expecting a header).
    * Once all data is received, it extracts the `nonce`, `tag`, and `ciphertext` from the buffer.
    * Uses the shared `AES_KEY`, `nonce`, and `tag` to decrypt the `ciphertext` via `AES.MODE_GCM`. GCM mode automatically verifies integrity using the tag.
    * If decryption and verification succeed, it decodes the result back to a string and prints it.
    * (Optional) Executes the string as a command.

## Evasion Considerations & Limitations

* **Content Obfuscation:** AES completely hides the payload content from network inspection tools that don't have the key.
* **Signature Avoidance:** Chunking breaks up the data, potentially avoiding simple IDS signatures that look for large, contiguous suspicious blobs. Variable timing makes the traffic less uniform.
* **Metadata Analysis:** Firewalls/IPS still see connection metadata (IPs, ports, protocol). Encrypted traffic on unexpected ports (like 4445 here) can be flagged as suspicious.
* **Traffic Volume:** Large payload transfers, even chunked and encrypted, can still be anomalous.
* **Behavioral Analysis:** Endpoint Detection and Response (EDR) systems on the receiver might detect the script's behavior (listening on a port, decrypting data, potentially spawning processes if execution is enabled) as malicious.
* **Key Security:** Hardcoded keys are easily extracted from the scripts if compromised.
* **GCM Nonce Reuse:** Reusing a nonce with the same key in GCM mode is catastrophic for security (though unlikely with `Crypto.Random`).

These techniques add layers of obfuscation but should be seen as basic steps, not a guaranteed path past modern defenses.