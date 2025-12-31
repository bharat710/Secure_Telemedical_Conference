import socket
import random
import time
import sympy
import hashlib
import os
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------- Signature Functions & Parameters --------------------
def mod_inverse(a, m):
    return pow(a, -1, m)

def elgamal_sign(message, p, g, x):
    """Generate an ElGamal signature for a given message."""
    hm = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if sympy.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (hm - x * r)) % (p - 1)
    return (r, s)

def elgamal_verify(message, signature, p, g, y):
    """Verify an ElGamal signature for a given message."""
    r, s = signature
    if not (0 < r < p):
        return False, None, None, None, None
    hm = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
    left = pow(g, hm, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right, hm, left, right, (r, s)

# Signature parameters (example only)
SIGN_P = 104729
SIGN_G = 2

# Patient's signing key pair
PAT_SIGN_PRIV = 12345
PAT_SIGN_PUB = pow(SIGN_G, PAT_SIGN_PRIV, SIGN_P)

# Doctor's public signing key (must match server's DOC_SIGN_PUB)
DOC_SIGN_PUB = pow(SIGN_G, 54321, SIGN_P)
# ---------------------------------------------------------------------------

# Extract Patient Device ID (ID_Di) from file name
filename = os.path.basename(__file__)
match = re.search(r'\d+', filename)
if match:
    ID_Di = match.group()
else:
    ID_Di = "Unknown"

DOCTOR_ID = "GWN"
DELTA_TS = 5  # seconds

def generate_keys():
    p = sympy.randprime(2**10, 2**12)
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return p, g, x, y

def encrypt(m, y, p, g):
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def hash_function(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

latest_global_hash = None
global_timing_printed = False

def print_client_timing(keygen_time, sign_time, session_time, global_time):
    print("\n[CLIENT] Execution Times:")
    print("{:<35} {:<15}".format("Operation", "Time (ms)"))
    print("-" * 50)
    print("{:<35} {:<15.3f}".format("Key Pair Generation", keygen_time * 1000))
    print("{:<35} {:<15.3f}".format("Sign Data Generation", sign_time * 1000))
    print("{:<35} {:<15.3f}".format("Session Key Computation", session_time * 1000))
    print("{:<35} {:<15.3f}".format("Global Hash Processing", global_time * 1000))
    print("-" * 50)

def run_client():
    global latest_global_hash, global_timing_printed
    while True:
        client = None
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", 5004))
            print(f"\n[CLIENT] Connected to Server as Patient Device #{ID_Di}!")
            
            # Step 1: Send client's public key parameters
            start_keygen = time.time()
            p, g, x_client, y_client = generate_keys()
            end_keygen = time.time()
            client_keygen_time = end_keygen - start_keygen
            client.sendall(f"{p} {g} {y_client}".encode())
            print(f"[CLIENT] Sent initial key parameters: p={p}, g={g}, y_client={y_client}")
            
            # Step 2: Receive server's public key
            y_server = int(client.recv(1024).decode())
            print(f"[CLIENT] Received server public key: y_server={y_server}")
            
            # Step 3: Send authentication request (Opcode 10)
            TSi = int(time.time())
            RNi = random.randint(1000, 9999)
            KDi_GWN = random.randint(2, p - 2)
            c1, c2 = encrypt(KDi_GWN, y_server, p, g)
            message_for_sign1 = f"{TSi}{RNi}{DOCTOR_ID}{c1}{c2}"
            signature1 = elgamal_sign(message_for_sign1, SIGN_P, SIGN_G, PAT_SIGN_PRIV)
            SignData1_str = f"{signature1[0]}|{signature1[1]}"
            auth_message = f"10 {TSi} {RNi} {DOCTOR_ID} {ID_Di} {c1} {c2} {SignData1_str}"
            client.sendall(auth_message.encode())
            print(f"[CLIENT] Sent (Opcode 10): {auth_message}")
            
            # Step 4: Receive server's response (Opcode 20)
            parts = client.recv(1024).decode().split()
            if len(parts) < 6 or parts[0] != "20":
                print("[CLIENT] Invalid response from server.")
                client.close()
                return
            TSGWN = int(parts[1])
            RNGWN = int(parts[2])
            recv_patient_id = parts[3]
            EKUDi = parts[4]
            SignData2_str = parts[5]
            print(f"[CLIENT] Received (Opcode 20): TSGWN={TSGWN}, RNGWN={RNGWN}, ID_Di={recv_patient_id}, EKUDi={EKUDi}, SignData2={SignData2_str}")
            
            if recv_patient_id != ID_Di:
                print("[CLIENT] Patient Device ID mismatch!")
                client.close()
                return
            
            TSGWN_received = int(time.time())
            if abs(TSGWN_received - TSGWN) > DELTA_TS:
                print(f"[CLIENT] Server response timestamp verification failed! |{TSGWN_received} - {TSGWN}| > {DELTA_TS}")
                client.close()
                return
            print("[CLIENT] Server response timestamp verified.")
            
            # Step 5: Verify doctor's signature on response with debug output
            message_for_sign2 = f"{TSGWN}{RNGWN}{ID_Di}{EKUDi}"
            try:
                r_str, s_str = SignData2_str.split("|")
                signature2 = (int(r_str), int(s_str))
            except Exception as e:
                print(f"[CLIENT] Failed to parse doctor's signature: {e}")
                client.close()
                return
            valid, hm, left, right, sig = elgamal_verify(message_for_sign2, signature2, SIGN_P, SIGN_G, DOC_SIGN_PUB)
            if not valid:
                print("[CLIENT] Doctor's ElGamal signature verification FAILED!")
                print("[CLIENT] Debug Info for Signature Verification:")
                print("   Message:", message_for_sign2)
                print("   Parsed Signature (r, s):", signature2)
                print("   Computed hm:", hm)
                print("   Left side (g^hm mod p):", left)
                print("   Right side (DOC_SIGN_PUB^r * r^s mod p):", right)
                client.close()
                return
            print("[CLIENT] Doctor's signature verified.")
            
            # Step 6: Compute session key and send verifier
            start_session = time.time()
            SKGWN_Di = hash_function(f"{KDi_GWN}{TSi}{TSGWN}{RNi}{RNGWN}{ID_Di}")
            end_session = time.time()
            client_session_time = end_session - start_session
            TS_prime = int(time.time())
            SKV_Di_GWN = hash_function(f"{SKGWN_Di}{TS_prime}")
            client.sendall(f"{SKV_Di_GWN} {TS_prime}".encode())
            print(f"[CLIENT] Sent session key verification: {SKV_Di_GWN} {TS_prime}")
            print(f"[CLIENT] Final Session Key: {SKGWN_Di}")
            
            # Wait for further messages from the server.
            while True:
                data = client.recv(4096)
                if not data:
                    print("[CLIENT] Server closed connection. Terminating client.")
                    return
                for line in data.decode().splitlines():
                    if line.startswith("60"):
                        print("[CLIENT] Received (Opcode 60): DISCONNECT. Terminating client.")
                        return
                    elif line.startswith("30"):
                        start_global = time.time()
                        latest_global_hash = line.split(maxsplit=1)[1]
                        _ = bytes.fromhex(latest_global_hash)
                        end_global = time.time()
                        client_global_time = end_global - start_global
                        if not global_timing_printed:
                            print_client_timing(client_session_time, client_session_time, client_session_time, client_global_time)
                            global_timing_printed = True
                        print(f"[CLIENT] Received (Opcode 30): Global Group Key: {latest_global_hash}")
                    elif line.startswith("40"):
                        payload_b64 = line.split(maxsplit=1)[1]
                        print(f"[CLIENT] Received (Opcode 40): Encrypted Message: {payload_b64}")
                        if not latest_global_hash:
                            print("[CLIENT] No global group key available, cannot decrypt message.")
                            continue
                        try:
                            key = bytes.fromhex(latest_global_hash)
                            payload = base64.b64decode(payload_b64)
                            iv = payload[:16]
                            ciphertext = payload[16:]
                            cipher = AES.new(key, AES.MODE_CBC, iv)
                            padded_plaintext = cipher.decrypt(ciphertext)
                            plaintext = unpad(padded_plaintext, AES.block_size).decode()
                            print(f"[CLIENT] Decrypted Message (Opcode 50): {plaintext}")
                        except Exception as e:
                            print(f"[CLIENT] Error decrypting message: {e}")
                    else:
                        print(f"[CLIENT] Received: {line}")
        except KeyboardInterrupt:
            print("\n[CLIENT] KeyboardInterrupt detected. Shutting down client.")
            if client:
                try:
                    client.close()
                except:
                    pass
            return
        except Exception as e:
            print(f"[CLIENT] Error: {e}. Terminating client.")
            if client:
                try:
                    client.close()
                except:
                    pass
            return

if __name__ == "__main__":
    run_client()
