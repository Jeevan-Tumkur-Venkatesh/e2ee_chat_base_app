import time
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def hkdf_expand(key_material: bytes, info: bytes, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)


def measure_time(func, loops=1000):
    start = time.time()
    for _ in range(loops):
        func()
    end = time.time()
    avg = (end - start) / loops
    return avg * 1000  # milliseconds


def main():
    print("===== PERFORMANCE EVALUATION =====\n")

    # -------------------------------
    # 1. X25519 Key Exchange Time
    # -------------------------------
    def bench_x25519():
        a = x25519.X25519PrivateKey.generate()
        b = x25519.X25519PrivateKey.generate()
        a.exchange(b.public_key())

    x25519_time = measure_time(bench_x25519, loops=200)
    print(f"X25519 Key Exchange (avg): {x25519_time:.4f} ms")

    # -------------------------------
    # 2. HKDF Derivation Time
    # -------------------------------
    def bench_hkdf():
        hkdf_expand(os.urandom(32), b"/test")

    hkdf_time = measure_time(bench_hkdf, loops=1000)
    print(f"HKDF Derivation (avg):      {hkdf_time:.4f} ms")

    # -------------------------------
    # 3. ChaCha20-Poly1305 Encryption/Decryption
    # -------------------------------
    key = os.urandom(32)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    plaintext = b"A" * 256

    def bench_encrypt():
        aead.encrypt(nonce, plaintext, b"")

    def bench_decrypt():
        ct = aead.encrypt(nonce, plaintext, b"")
        aead.decrypt(nonce, ct, b"")

    enc_time = measure_time(bench_encrypt, loops=1000)
    dec_time = measure_time(bench_decrypt, loops=1000)

    print(f"ChaCha20 Encryption (avg):  {enc_time:.4f} ms")
    print(f"ChaCha20 Decryption (avg):  {dec_time:.4f} ms")

    # -------------------------------
    # 4. Per-Message Key Derivation Cost
    # -------------------------------
    def bench_msg_hkdf():
        hkdf_expand(key + nonce, b"/msg")

    msg_kdf_time = measure_time(bench_msg_hkdf, loops=1000)
    print(f"Per-Message HKDF (avg):     {msg_kdf_time:.4f} ms")

    # -------------------------------
    # 5. Ratchet Cost
    # -------------------------------
    def bench_ratchet():
        hkdf_expand(key, b"/ratchet")

    ratchet_time = measure_time(bench_ratchet, loops=1000)
    print(f"Ratchet Step (avg):         {ratchet_time:.4f} ms")

    # -------------------------------
    # 6. Message Size Overhead
    # -------------------------------
    ct = aead.encrypt(nonce, plaintext, b"")
    overhead = len(ct) - len(plaintext)

    print(f"\nMessage Size Overhead:      {overhead} bytes")

    print("\n===== DONE =====")


if __name__ == "__main__":
    main()
