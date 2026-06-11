from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def hkdf_derive(key: bytes, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"test-info",
    )
    return hkdf.derive(key)

def test_encrypt_decrypt():
    print("Running encryption/decryption test...")

    key = os.urandom(32)
    aead = ChaCha20Poly1305(key)

    nonce = os.urandom(12)
    plaintext = b"Hello Test Message"

    ciphertext = aead.encrypt(nonce, plaintext, b"")
    recovered = aead.decrypt(nonce, ciphertext, b"")

    if recovered == plaintext:
        print("✔ Decryption matches original message.")
    else:
        print("❌ Decryption failed!")

def test_tamper_detection():
    print("\nRunning tamper detection test...")

    key = os.urandom(32)
    aead = ChaCha20Poly1305(key)

    nonce = os.urandom(12)
    plaintext = b"Auth Test"

    ciphertext = aead.encrypt(nonce, plaintext, b"")

    # Modify one byte of ciphertext to simulate tampering
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0x01

    try:
        aead.decrypt(nonce, bytes(tampered), b"")
        print("❌ Tampering not detected! (This should not happen)")
    except Exception:
        print("✔ Tamper detection working (auth error raised).")

def main():
    print("===== Starting Crypto Tests =====\n")
    test_encrypt_decrypt()
    test_tamper_detection()
    print("\nAll tests completed.\n")

if __name__ == "__main__":
    main()
