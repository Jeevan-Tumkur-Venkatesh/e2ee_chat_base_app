# e2ee_chat_base_app

This is a Python-based end-to-end encrypted chat application. I built this project to understand how secure messaging works internally and how cryptographic concepts like key exchange, key derivation, authenticated encryption, replay protection, and key ratcheting can be used together in a real implementation.

The project uses X25519 for key exchange, HKDF for deriving keys, and ChaCha20-Poly1305 AEAD for encrypting and authenticating messages.

## Overview

In this project, I implemented a basic encrypted communication protocol between a client and a server. Both sides first perform a secure handshake using X25519 Diffie-Hellman key exchange. After that, HKDF is used to derive separate send and receive keys. Once the keys are ready, messages are encrypted using ChaCha20-Poly1305.

I also added extra security features like message-level key diversification, nonce management, lightweight key ratcheting, TTL validation, session expiry, and Bloom filter based replay protection.

This project was mainly done to learn how secure chat applications work behind the scenes. It is inspired by the ideas used in modern secure messaging systems, but it is a simplified educational implementation.

## Key Features

* End-to-end encrypted client-server chat
* X25519 Diffie-Hellman key exchange
* HKDF-based key derivation
* ChaCha20-Poly1305 authenticated encryption
* Separate send and receive keys
* Message-level key diversification
* Unique nonce generation using prefix and counter
* Lightweight key ratcheting every 5 messages
* Bloom filter based replay protection
* Message TTL validation
* Session expiration
* Tamper detection for modified ciphertext
* Test script for encryption and decryption correctness
* Performance benchmark for crypto operations

## Tech Stack

* Python
* `cryptography` library
* X25519
* HKDF
* ChaCha20-Poly1305 AEAD
* Bloom Filter
* Socket Programming

## Why I Built This

I wanted to understand cryptography not just from theory, but also from implementation. During my cryptography coursework, I studied concepts like key exchange, encryption, hashing, message authentication, replay attacks, and forward secrecy. This project helped me connect those concepts with actual code.

Instead of only doing basic encryption and decryption, I tried to add more realistic security features such as replay protection, key ratcheting, TTL checks, and nonce safety.

## How It Works

1. The server starts and waits for a client connection.
2. The client connects to the server.
3. Both client and server generate X25519 key pairs.
4. Public keys are exchanged during the handshake.
5. Both sides derive the same shared secret.
6. HKDF is used to create independent send keys, receive keys, nonce prefixes, and ratchet keys.
7. Every message is encrypted and authenticated using ChaCha20-Poly1305 AEAD.
8. A unique nonce is created for each message using an 8-byte prefix and a 4-byte counter.
9. Each message has an ID and timestamp.
10. The receiver checks message TTL to reject stale messages.
11. A Bloom filter is used to detect and reject replayed messages.
12. After every 5 messages, the keys are updated using lightweight ratcheting.

## Security Concepts Covered

| Security Concept  | How It Is Used                                    |
| ----------------- | ------------------------------------------------- |
| Confidentiality   | Messages are encrypted using ChaCha20             |
| Integrity         | Poly1305 authentication detects message tampering |
| Key Exchange      | X25519 is used to derive a shared secret          |
| Key Derivation    | HKDF derives separate cryptographic keys          |
| Nonce Safety      | Prefix + counter method avoids nonce reuse        |
| Replay Protection | Bloom filter tracks message IDs                   |
| Message Freshness | TTL validation rejects old messages               |
| Key Update        | Lightweight ratcheting updates keys periodically  |
| Tamper Detection  | Modified ciphertext fails during decryption       |

## Project Structure

```text
e2ee_chat_base_app/
├── chat.py
├── tests.py
├── performance_test.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Jeevan-Tumkur-Venkatesh/e2ee_chat_base_app.git
cd e2ee_chat_base_app
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Open two terminal windows.

In the first terminal, start the server:

```bash
python3 chat.py server
```

In the second terminal, start the client:

```bash
python3 chat.py client
```

Once the handshake is completed, both sides can start sending encrypted messages.

## Running Tests

To run the test file:

```bash
python3 tests.py
```

The test script checks:

* Whether encryption and decryption are working correctly
* Whether decrypted messages match the original message
* Whether modified ciphertext is detected properly

## Running Performance Benchmark

To run the performance test:

```bash
python3 performance_test.py
```

This measures the time taken for important cryptographic operations like:

* X25519 key exchange
* HKDF key derivation
* ChaCha20-Poly1305 encryption
* ChaCha20-Poly1305 decryption
* Key ratcheting

## What I Learned

Through this project, I got better understanding of:

* How secure handshakes work
* Why key derivation is important
* Why nonce reuse is dangerous
* How authenticated encryption protects both privacy and integrity
* How replay attacks can be detected
* Why keys should be updated over time
* How secure messaging protocols are designed in practice

## Limitations

This is an educational project and should not be used in production.

Some limitations are:

* It does not implement the full Signal Double Ratchet protocol
* It does not use persistent identity keys
* It does not have certificate-based authentication
* It does not support group chat
* It does not support encrypted file transfer
* It does not include formal security verification
* It is mainly built to demonstrate the concepts clearly

## Future Improvements

Some improvements I would like to add later:

* Persistent identity keys
* Mutual authentication
* Full Double Ratchet style key update
* Group messaging
* Encrypted file transfer
* Docker support
* Better command-line interface
* Structured logging
* GitHub Actions for automated testing
* Demo screenshots and architecture diagram

## Resume Summary

Python-based end-to-end encrypted chat application using X25519 key exchange, HKDF key derivation, ChaCha20-Poly1305 AEAD encryption, lightweight key ratcheting, TTL validation, and Bloom filter replay protection.

## Disclaimer

This project is only for learning and demonstration purposes. Cryptography is very sensitive, and production systems should use well-tested, audited, and standardized security protocols.
