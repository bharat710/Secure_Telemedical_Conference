import socket
import threading
import random
import time
import sympy
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------- Signature Functions & Parameters --------------------
def mod_inverse(a, m):
    return pow(a, -1, m)

def elgamal_sign(message, p, g, x):
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
    r, s = signature
    if not (0 < r < p):
        return False
    hm = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
    left = pow(g, hm, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# Signature parameters (example only; use large parameters in production)
SIGN_P = 104729
SIGN_G = 2

# Doctor's signing key pair
DOC_SIGN_PRIV = 54321
DOC_SIGN_PUB = pow(SIGN_G, DOC_SIGN_PRIV, SIGN_P)
# Patient's public signing key MUST be computed from the patient's private key.
PAT_SIGN_PRIV = 12345
PAT_SIGN_PUB = pow(SIGN_G, PAT_SIGN_PRIV, SIGN_P)  # <-- Updated!

# ---------------------------------------------------------------------------

# Global storage for active session keys and client connections
session_keys = {}       # Maps client socket to their session key
client_connections = [] # Active client sockets
server_private_key = None  # Set when the server's key is generated

# Blocklist: maps patient ID (ID_Di) to the timestamp when blocked
blocklist = {}

DOCTOR_ID = "GWN"
DELTA_TS = 5  # seconds

def generate_keys():
    global server_private_key
    p = sympy.randprime(2**10, 2**12)
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    server_private_key = x
    return p, g, x, y

def decrypt(c1, c2, x, p):
    s = pow(c1, x, p)
    return (c2 * mod_inverse(s, p)) % p

def hash_function(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

def compute_global_hash(connections):
    start_global = time.time()
    if not connections:
        return None, 0
    # Only use session keys from the provided connections
    keys = [session_keys[conn] for conn in connections if conn in session_keys]
    if not keys:
        return None, 0
    combined = "||".join(keys) + f"||{server_private_key}"
    result = hash_function(combined)
    end_global = time.time()
    return result, end_global - start_global

def broadcast_message(connections, is_global_hash=False, message=None):
    if not connections:
        print("[SERVER] No clients to broadcast to.")
        return
    
    global_hash, global_hash_time = compute_global_hash(connections)
    if not global_hash:
        print("[SERVER] Cannot compute group key for selected clients.")
        return
    
    print("\n[SERVER] Global Hash Processing Time:")
    print("{:<35} {:<15.3f}".format("Global Hash Computation", global_hash_time * 1000))
    
    # First send the global hash
    hash_msg = "30 " + global_hash + "\n"
    print(f"[SERVER] Broadcasting (Opcode 30) to {len(connections)} clients: {global_hash}")
    for conn in list(connections):
        try:
            conn.sendall(hash_msg.encode())
        except Exception as e:
            print(f"[SERVER] Error sending to client: {e}")
            if conn in client_connections:
                client_connections.remove(conn)
            if conn in session_keys:
                del session_keys[conn]
    
    # If we're only sending the global hash, we're done
    if is_global_hash or not message:
        return
    
    # Encrypt and send the message
    start_encrypt = time.time()
    try:
        key = bytes.fromhex(global_hash)
    except ValueError as e:
        print(f"[SERVER] Error converting global hash to key: {e}")
        return
    
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_msg)
    payload_data = base64.b64encode(iv + ciphertext).decode()
    end_encrypt = time.time()
    encrypt_time = end_encrypt - start_encrypt
    
    print("\n[SERVER] Message Encryption Time:")
    print("{:<35} {:<15.3f}".format("Message Encryption", encrypt_time * 1000))
    
    payload = "40 " + payload_data + "\n"
    
    print(f"[SERVER] Broadcasting (Opcode 40) to {len(connections)} clients: {payload_data}")
    for conn in list(connections):
        try:
            conn.sendall(payload.encode())
        except Exception as e:
            print(f"[SERVER] Error sending to client: {e}")
            if conn in client_connections:
                client_connections.remove(conn)
            if conn in session_keys:
                del session_keys[conn]

def doctor_command_thread():
    try:
        while True:
            print("\n[SERVER] Doctor Command Options:")
            print("1. Send broadcast message")
            print("2. View connected clients")
            print("3. Close all connections and exit")
            choice = input("Enter choice (1-3): ").strip()
            
            if choice == "1":
                # Take a snapshot of currently connected clients
                current_connections = list(client_connections)
                if not current_connections:
                    print("[SERVER] No clients connected. Cannot broadcast.")
                    continue
                
                print(f"[SERVER] {len(current_connections)} clients will receive this broadcast.")
                msg = input("Enter message to broadcast: ")
                broadcast_message(current_connections, is_global_hash=False, message=msg)
            
            elif choice == "2":
                if not client_connections:
                    print("[SERVER] No clients connected.")
                else:
                    print(f"[SERVER] Connected clients: {len(client_connections)}")
                    for i, conn in enumerate(client_connections):
                        print(f"  Client {i+1}: {conn.getpeername()}")
            
            elif choice == "3":
                print("[SERVER] Closing all connections and exiting...")
                for conn in list(client_connections):
                    try:
                        conn.sendall("60 DISCONNECT\n".encode())
                        conn.close()
                    except:
                        pass
                client_connections.clear()
                session_keys.clear()
                os._exit(0)  # Force exit all threads
            
            else:
                print("[SERVER] Invalid choice. Please try again.")
    
    except KeyboardInterrupt:
        print("\n[SERVER] Doctor command thread received KeyboardInterrupt.")
        for conn in list(client_connections):
            try:
                conn.sendall("60 DISCONNECT\n".encode())
                conn.close()
            except:
                pass
        client_connections.clear()
        session_keys.clear()
        os._exit(0)  # Force exit all threads

def handle_client(conn, addr):
    global session_keys, client_connections, blocklist
    print(f"\n[SERVER] Connected to client: {addr}")
    try:
        # Step 1: Receive client's public key parameters: p, g, y_client
        data = conn.recv(1024).decode()
        if not data:
            conn.close()
            return
        p, g, y_client = map(int, data.split())
        print(f"[SERVER] Received (Initial Key Exchange) from {addr}: p={p}, g={g}, y_client={y_client}")
        
        # Step 2: Generate server's ephemeral key and send y_server
        start_keygen = time.time()
        x_server = random.randint(2, p - 2)
        y_server = pow(g, x_server, p)
        end_keygen = time.time()
        server_keygen_time = end_keygen - start_keygen
        
        conn.sendall(str(y_server).encode())
        print(f"[SERVER] Sent y_server to {addr}: {y_server}")
        
        # Step 3: Receive authentication request (Opcode 10)
        # Format: "10 TSi RNi DOCTOR_ID ID_Di c1 c2 SignData1"
        parts = conn.recv(1024).decode().split()
        if len(parts) < 8 or parts[0] != "10":
            print(f"[SERVER] {addr} - Invalid authentication message format.")
            conn.close()
            return
        TSi = int(parts[1])
        RNi = int(parts[2])
        recv_doctor_id = parts[3]
        patient_id = parts[4]
        c1 = int(parts[5])
        c2 = int(parts[6])
        SignData1_str = parts[7]  # in "r|s" format
        print(f"[SERVER] Received (Opcode 10) from {addr}: TSi={TSi}, RNi={RNi}, ID_GWN={recv_doctor_id}, ID_Di={patient_id}, c1={c1}, c2={c2}, SignData1={SignData1_str}")
        
        if recv_doctor_id != DOCTOR_ID:
            print(f"[SERVER] {addr} - Invalid doctor identity: {recv_doctor_id}.")
            conn.close()
            return
        
        current_time = time.time()
        if patient_id in blocklist:
            block_timestamp = blocklist[patient_id]
            if current_time < block_timestamp + 60:
                print(f"[SERVER] {addr} - Patient {patient_id} is blocked until {block_timestamp + 60:.0f}.")
                conn.close()
                return
            else:
                del blocklist[patient_id]
        
        TS_received = int(time.time())
        if abs(TS_received - TSi) > DELTA_TS:
            print(f"[SERVER] {addr} - Timestamp verification failed! |{TS_received} - {TSi}| > {DELTA_TS}")
            conn.close()
            return
        print(f"[SERVER] {addr} - Timestamp verified.")
        
        # Validate signature using ElGamal
        start_verify = time.time()
        message_for_sign1 = f"{TSi}{RNi}{DOCTOR_ID}{c1}{c2}"
        try:
            r_str, s_str = SignData1_str.split("|")
            signature1 = (int(r_str), int(s_str))
        except Exception as e:
            print(f"[SERVER] {addr} - Failed to parse signature: {e}")
            conn.close()
            return
        
        signature_valid = elgamal_verify(message_for_sign1, signature1, SIGN_P, SIGN_G, PAT_SIGN_PUB)
        end_verify = time.time()
        signature_verify_time = end_verify - start_verify
        
        if not signature_valid:
            print(f"[SERVER] {addr} - ElGamal signature verification failed!")
            conn.close()
            return
        print(f"[SERVER] {addr} - ElGamal signature validated.")
        
        # Step 4: Decrypt session key KDi,GWN
        KDi_GWN = decrypt(c1, c2, x_server, p)
        print(f"[SERVER] {addr} - Decrypted KDi,GWN: {KDi_GWN}")
        
        # Step 5: Respond with session token (Opcode 20)
        start_sign = time.time()
        TSGWN = int(time.time())
        RNGWN = random.randint(1000, 9999)
        r_val = random.randint(2, p - 2)
        c1_resp = pow(g, r_val, p)
        c2_resp = (KDi_GWN * pow(y_client, r_val, p)) % p
        EKUDi = base64.b64encode(f"{c1_resp} {c2_resp}".encode()).decode()
        message_for_sign2 = f"{TSGWN}{RNGWN}{patient_id}{EKUDi}"
        signature2 = elgamal_sign(message_for_sign2, SIGN_P, SIGN_G, DOC_SIGN_PRIV)
        end_sign = time.time()
        signature_gen_time = end_sign - start_sign
        
        SignData2_str = f"{signature2[0]}|{signature2[1]}"
        response = f"20 {TSGWN} {RNGWN} {patient_id} {EKUDi} {SignData2_str}"
        conn.sendall(response.encode())
        print(f"[SERVER] Sent (Opcode 20) to {addr}: {response}")
        
        # Step 6: Receive session key verification from client
        parts = conn.recv(1024).decode().split()
        if len(parts) < 2:
            conn.close()
            return
        SKV_received, TS_prime = parts[0], int(parts[1])
        
        # Compute the session key
        start_session = time.time()
        SKGWN_Di = hash_function(f"{KDi_GWN}{TSi}{TSGWN}{RNi}{RNGWN}{patient_id}")
        expected_SKV = hash_function(f"{SKGWN_Di}{TS_prime}")
        end_session = time.time()
        session_key_time = end_session - start_session
        
        if expected_SKV == SKV_received:
            print(f"[SERVER] {addr} - Authentication Successful!")
            print(f"[SERVER] {addr} - Final Session Key: {SKGWN_Di}")
            
            # Add client to the list of connections and store session key
            client_connections.append(conn)
            session_keys[conn] = SKGWN_Di
            
            print("\n[SERVER] Execution Times for Client", addr)
            print("{:<35} {:<15}".format("Operation", "Time (ms)"))
            print("-" * 50)
            print("{:<35} {:<15.3f}".format("Key Pair Generation", server_keygen_time * 1000))
            print("{:<35} {:<15.3f}".format("Sign Data Generation", signature_gen_time * 1000))
            print("{:<35} {:<15.3f}".format("Signature Verification", signature_verify_time * 1000))
            print("{:<35} {:<15.3f}".format("Session Key Computation", session_key_time * 1000))
            print("-" * 50)
            
            # Keep connection open
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
            except:
                pass
            
            # If we reach here, client disconnected
            print(f"[SERVER] Client {addr} disconnected.")
            if conn in client_connections:
                client_connections.remove(conn)
            if conn in session_keys:
                del session_keys[conn]
        else:
            print(f"[SERVER] {addr} - Session key verification failed! Blocking patient {patient_id} for 60 seconds.")
            blocklist[patient_id] = time.time()
            conn.close()
    except Exception as e:
        print(f"[SERVER] Error with {addr}: {e}")
        if conn in client_connections:
            client_connections.remove(conn)
        if conn in session_keys:
            del session_keys[conn]
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5004))
    server.listen()
    print("\n[SERVER] Doctor's device (GWN) listening on port 5004...")
    
    # Start the doctor command thread
    threading.Thread(target=doctor_command_thread, daemon=True).start()
    
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER] KeyboardInterrupt detected. Shutting down server...")
    finally:
        for conn in list(client_connections):
            try:
                conn.sendall("60 DISCONNECT\n".encode())
            except Exception as e:
                print(f"[SERVER] Error sending disconnect to client: {e}")
        for conn in list(client_connections):
            try:
                conn.close()
            except:
                pass
        server.close()
        print("[SERVER] Server shutdown complete.")

if __name__ == "__main__":
    main()