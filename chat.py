#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import threading
import time
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ----------------------- Protocol constants -----------------------

INFO_LABEL = b"adv-e2ee-protocol-v1"
RATCHET_INTERVAL = 5           # ratchet every 5 messages
BLOOM_SIZE_BITS = 4096         # 4096-bit bloom filter
BLOOM_HASHES = 3               # number of bloom filter hash functions


# ----------------------- Utility helpers -----------------------

def hkdf_expand(key_material: bytes, info_suffix: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 expansion helper."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=INFO_LABEL + info_suffix,
    )
    return hkdf.derive(key_material)


def pack_nonce(prefix: bytes, counter: int) -> bytes:
    """Create 12-byte nonce = 8-byte prefix + 4-byte counter."""
    return prefix + struct.pack(">I", counter)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed frame."""
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes, or raise if socket closes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def recv_frame(sock: socket.socket) -> bytes:
    """Receive a length-prefixed frame."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)


# ----------------------- Bloom Filter for replay protection -----------------------

class BloomFilter:
    def __init__(self, size_bits=BLOOM_SIZE_BITS, num_hashes=BLOOM_HASHES):
        self.size_bits = size_bits
        self.num_hashes = num_hashes
        self.bits = 0  # use Python int as bit array

    def _hashes(self, data: bytes):
        h1 = int.from_bytes(hashlib.sha256(data + b"0").digest()[:8], "big")
        h2 = int.from_bytes(hashlib.sha256(data + b"1").digest()[:8], "big")
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size_bits

    def check_and_add(self, data: bytes) -> bool:
        """
        Returns True if data was ALREADY seen (probable replay),
        or False if this is the first time.
        """
        seen = True
        for idx in self._hashes(data):
            mask = 1 << idx
            if not (self.bits & mask):
                seen = False
                self.bits |= mask
        return seen


# ----------------------- Secure encrypted channel -----------------------

class Channel:
    def __init__(
        self,
        sock: socket.socket,
        send_base_key: bytes,
        recv_base_key: bytes,
        send_prefix: bytes,
        recv_prefix: bytes,
        ttl_seconds: int,
        session_ttl_seconds: int,
    ):
        self.sock = sock

        # base keys used for per-message HKDF and ratcheting
        self.send_base_key = send_base_key
        self.recv_base_key = recv_base_key

        self.send_prefix = send_prefix
        self.recv_prefix = recv_prefix

        self.send_counter = 0
        self.recv_counter = 0

        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()

        self.ttl = ttl_seconds
        self.session_ttl = session_ttl_seconds
        self.session_start = time.time()

        self.replay_filter = BloomFilter()
        self.closed = False

    # -------- Session helpers --------

    def _session_alive(self) -> bool:
        if self.session_ttl <= 0:
            return True
        if (time.time() - self.session_start) > self.session_ttl:
            print("[*] Session TTL expired. Further messages blocked.")
            return False
        return True

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.sock.close()

    # -------- Sending --------

    def send_msg(self, text: str) -> None:
        if not self._session_alive():
            print("[*] Not sending message because session expired.")
            return

        ts = int(time.time())
        msg_id = os.urandom(8)  # 64-bit random ID
        payload = struct.pack(">I", ts) + msg_id + text.encode("utf-8")

        with self.send_lock:
            self.send_counter += 1
            counter = self.send_counter

            nonce = pack_nonce(self.send_prefix, counter)

            # HKDF per-message key diversification (same info string on both sides)
            msg_key = hkdf_expand(self.send_base_key + nonce, b"/msg")

            # Ratchet every RATCHET_INTERVAL messages
            if counter % RATCHET_INTERVAL == 0:
                self.send_base_key = hkdf_expand(self.send_base_key, b"/ratchet")
                print(f"[*] Send-side ratchet applied at message #{counter}")

        aead = ChaCha20Poly1305(msg_key)
        ciphertext = aead.encrypt(nonce, payload, b"")

        try:
            send_frame(self.sock, ciphertext)
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            self.close()

    # -------- Receiving --------

    def recv_msg(self):
        if not self._session_alive():
            return None

        try:
            ct = recv_frame(self.sock)
        except ConnectionError:
            self.close()
            return None
        except Exception as e:
            print(f"[!] Error receiving frame: {e}")
            self.close()
            return None

        with self.recv_lock:
            self.recv_counter += 1
            counter = self.recv_counter

            nonce = pack_nonce(self.recv_prefix, counter)

            # HKDF per-message key diversification – SAME info string as send side
            msg_key = hkdf_expand(self.recv_base_key + nonce, b"/msg")

            # Ratchet every RATCHET_INTERVAL messages
            if counter % RATCHET_INTERVAL == 0:
                self.recv_base_key = hkdf_expand(self.recv_base_key, b"/ratchet")
                print(f"[*] Receive-side ratchet applied at message #{counter}")

        aead = ChaCha20Poly1305(msg_key)

        try:
            pt = aead.decrypt(nonce, ct, b"")
        except Exception:
            print("[!] Authentication failed. Possible tampered ciphertext.")
            return None

        if len(pt) < 12:
            print("[!] Invalid plaintext format.")
            return None

        ts = struct.unpack(">I", pt[:4])[0]
        msg_id = pt[4:12]
        body = pt[12:]

        # Bloom filter replay detection
        if self.replay_filter.check_and_add(msg_id):
            print("[!] Replay detected. Discarded.")
            return None
        else:
            print("[*] New message accepted (replay filter updated).")

        # TTL check
        if self.ttl > 0 and (time.time() - ts) > self.ttl:
            print("[!] TTL exceeded. Message expired.")
            return None

        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            print("[!] Failed to decode message text.")
            return None


# ----------------------- Handshake (X25519 + HKDF) -----------------------

def do_handshake_server(conn: socket.socket):
    """Server side handshake: receive client pubkey, send own pubkey, derive shared secret."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()

    client_pub_bytes = recv_exact(conn, 32)
    conn.sendall(pub)

    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = priv.exchange(client_pub)

    # Derive root key and split into send/recv keys
    root = hkdf_expand(shared, b"/root", length=64)
    send_key = root[:32]     # server -> client
    recv_key = root[32:]     # client -> server

    # Derive nonce prefixes
    nonce_seed = hkdf_expand(shared, b"/nonce", length=16)
    send_pref = nonce_seed[:8]
    recv_pref = nonce_seed[8:]

    print("[*] Server handshake complete.")
    return send_key, recv_key, send_pref, recv_pref


def do_handshake_client(sock: socket.socket):
    """Client side handshake: send pubkey, receive server pubkey, derive shared secret."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()

    sock.sendall(pub)
    server_pub_bytes = recv_exact(sock, 32)

    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = priv.exchange(server_pub)

    root = hkdf_expand(shared, b"/root", length=64)
    # From client view, directions flip
    recv_key = root[:32]     # server -> client
    send_key = root[32:]     # client -> server

    nonce_seed = hkdf_expand(shared, b"/nonce", length=16)
    recv_pref = nonce_seed[:8]
    send_pref = nonce_seed[8:]

    print("[*] Client handshake complete.")
    return send_key, recv_key, send_pref, recv_pref


# ----------------------- Communication loops -----------------------

def recv_loop(channel: Channel):
    while True:
        msg = channel.recv_msg()
        if msg is None:
            if channel.closed or not channel._session_alive():
                break
            continue  # just a dropped message (replay/TTL/etc.)
        print(f"[peer] {msg}")
    print("[*] Receive loop ending.")
    channel.close()


def run_server(host: str, port: int, ttl: int, session_ttl: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[*] Server listening on {host}:{port} ...")

        conn, addr = s.accept()
        print(f"[*] Client connected from {addr}")

        try:
            send_key, recv_key, send_pref, recv_pref = do_handshake_server(conn)
        except Exception as e:
            print(f"[!] Handshake failed: {e}")
            conn.close()
            return

        channel = Channel(conn, send_key, recv_key, send_pref, recv_pref, ttl, session_ttl)

        t = threading.Thread(target=recv_loop, args=(channel,), daemon=True)
        t.start()

        try:
            for line in iter(input, None):
                text = line.rstrip("\n")
                if not text:
                    continue
                if text.lower() in {"/quit", "/exit"}:
                    break
                channel.send_msg(text)
        except (EOFError, KeyboardInterrupt):
            pass

        print("[*] Server shutting down.")
        channel.close()
        t.join(timeout=1.0)


def run_client(host: str, port: int, ttl: int, session_ttl: int):
    with socket.create_connection((host, port)) as sock:
        print(f"[*] Connected to {host}:{port}")

        try:
            send_key, recv_key, send_pref, recv_pref = do_handshake_client(sock)
        except Exception as e:
            print(f"[!] Handshake failed: {e}")
            return

        channel = Channel(sock, send_key, recv_key, send_pref, recv_pref, ttl, session_ttl)

        t = threading.Thread(target=recv_loop, args=(channel,), daemon=True)
        t.start()

        try:
            for line in iter(input, None):
                text = line.rstrip("\n")
                if not text:
                    continue
                if text.lower() in {"/quit", "/exit"}:
                    break
                channel.send_msg(text)
        except (EOFError, KeyboardInterrupt):
            pass

        print("[*] Client shutting down.")
        channel.close()
        t.join(timeout=1.0)


# ----------------------- CLI entry -----------------------

def main():
    parser = argparse.ArgumentParser(
        description="Advanced E2EE Protocol with X25519, HKDF, ChaCha20-Poly1305, Ratcheting, Bloom-filter Replay Protection"
    )
    parser.add_argument("role", choices=["server", "client"])
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ttl", type=int, default=0, help="Message TTL in seconds (0 = no TTL)")
    parser.add_argument("--session-ttl", type=int, default=0, help="Session TTL in seconds (0 = no session TTL)")

    args = parser.parse_args()

    if args.role == "server":
        run_server(args.host, args.port, args.ttl, args.session_ttl)
    else:
        run_client(args.host, args.port, args.ttl, args.session_ttl)


if __name__ == "__main__":
    main()
