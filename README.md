# Assignment 2: Secure Telemedical Conference using Digital Signature

## Overview
This project implements a secure telemedical conferencing system that enables confidential communication between a doctor and multiple patients. The system uses cryptographic techniques including ElGamal encryption/digital signatures and AES encryption to ensure secure authentication, key exchange, and encrypted communication.

## Features
- Secure authentication between doctor and patient devices
- Session key establishment using ElGamal cryptosystem
- Message encryption using AES-256 in CBC mode
- Digital signature verification for data integrity
- Group key generation for secure broadcast messaging
- Timestamp verification to prevent replay attacks
- Blocking mechanism for failed authentication attempts
- Multi-threaded server to handle multiple patient connections

## Assumptions
- The doctor's device acts as a Gateway Node (GWN) in the system
- Each patient has a unique ID derived from their device filename
- The maximum allowable transmission delay (DELTA_TS) is set to 5 seconds
- All devices are time-synchronized within acceptable limits
- For demonstration purposes, smaller cryptographic parameters are used than would be in production
- The doctor and patients trust each other's public keys (pre-shared)

## Sequence of Steps
1. **Initialization Phase**:
   - Each participant generates ElGamal key pairs
   - Public keys are exchanged between parties

2. **Authentication and Key Exchange**:
   - Patient device sends authentication request to doctor with timestamp, random number, doctor ID, encrypted session key, and digital signature
   - Doctor verifies timestamp and signature, decrypts session key
   - Doctor sends response with timestamp, random number, patient ID, re-encrypted session key, and signature
   - Patient verifies timestamp and signature, calculates session key
   - Patient sends session key verification to doctor
   - Doctor verifies and establishes secure session or blocks patient on failure

3. **Secure Messaging Phase**:
   - Doctor computes group key from all established session keys
   - Messages are encrypted using AES-256 with the group key
   - All authenticated patients can decrypt and read the broadcast messages

## How It Works

### Key Generation
The ElGamal cryptosystem is used for key generation:
1. Select a prime number p and generator g
2. Choose a private key x randomly
3. Compute the public key y = g^x mod p

### Authentication Protocol
1. The patient device generates a timestamp (TSi) and random number (RNi)
2. The patient encrypts a session key (KDi,GWN) using the doctor's public key
3. The patient creates a signature (SignData1) over the authentication data
4. The doctor verifies the timestamp and signature, then decrypts the session key
5. The doctor responds with a timestamp (TSGWN), random number (RNGWN), and signature (SignData2)
6. The patient verifies the doctor's response and computes the session key
7. Both parties verify they have established the same session key

### Group Key Generation
After establishing session keys with multiple patients, the doctor:
1. Computes a group key by hashing all session keys combined with the server's private key
2. Broadcasts this group key to all connected patients
3. Uses the group key to encrypt broadcast messages

### Multithreaded Connection Handling
- The doctor's device uses threading to handle multiple patient connections simultaneously
- Each patient connection is processed in a separate thread
- A message input thread allows the doctor to broadcast messages to all connected patients

## Executing the Code

### Step 1: Start the Doctor's Server
```bash
python doctor.py
```

### Step 2: Start Patient Devices (in separate terminals)
```bash
python patient_1.py
```
You can start multiple patients by running additional instances:
```bash
python patient_2.py
python patient_3.py
# etc.
```

### Step 3: Sending Broadcast Messages
Once patients are connected, you can send broadcast messages from the doctor's server by entering text when prompted.

## Sample Input and Output

### Doctor's Server Output:
```
[SERVER] Doctor's device (GWN) listening on port 5003...

[SERVER] Connected to client: ('127.0.0.1', 52437)
[SERVER] Received (Initial Key Exchange) from ('127.0.0.1', 52437): p=2381, g=1570, y_client=1778
[SERVER] Sent y_server to ('127.0.0.1', 52437): 359
[SERVER] Received (Opcode 10) from ('127.0.0.1', 52437): TSi=1709978435, RNi=1234, ID_GWN=GWN, ID_Di=1, c1=2025, c2=1234, SignData1=64401|41483
[SERVER] ('127.0.0.1', 52437) - Timestamp verified.
[SERVER] ('127.0.0.1', 52437) - ElGamal signature validated.
[SERVER] ('127.0.0.1', 52437) - Decrypted KDi,GWN: 1234
[SERVER] Sent (Opcode 20) to ('127.0.0.1', 52437): 20 1709978436 5678 1 YzEgYzI= 64401|41483
[SERVER] ('127.0.0.1', 52437) - Authentication Successful!
[SERVER] ('127.0.0.1', 52437) - Final Session Key: a1b2c3d4e5f6

Enter message to broadcast: Hello patients! This is a secure message.
[SERVER] Broadcasting (Opcode 30): a1b2c3d4e5f6g7h8i9j0
[SERVER] Broadcasting (Opcode 40): Base64EncodedEncryptedMessage
```

### Patient's Output:
```
[CLIENT] Connected to Server as Patient Device #1!
[CLIENT] Sent initial key parameters: p=2381, g=1570, y_client=1778
[CLIENT] Received server public key: y_server=359
[CLIENT] Sent (Opcode 10): 10 1709978435 1234 GWN 1 2025 1234 64401|41483
[CLIENT] Received (Opcode 20): TSGWN=1709978436, RNGWN=5678, ID_Di=1, EKUDi=YzEgYzI=, SignData2=64401|41483
[CLIENT] Server response timestamp verified.
[CLIENT] Doctor's signature verified.
[CLIENT] Sent session key verification: a1b2c3d4e5f6 1709978437
[CLIENT] Final Session Key: a1b2c3d4e5f6

[CLIENT] Received (Opcode 30): Global Group Key: a1b2c3d4e5f6g7h8i9j0
[CLIENT] Received (Opcode 40): Encrypted Message: Base64EncodedEncryptedMessage
[CLIENT] Decrypted Message (Opcode 50): Hello patients! This is a secure message.
```

## Implementation Details

The project code is primarily implemented using **Python** programming language. Popular cryptographic libraries have been used to implement the encryption, decryption and hashing functions. Key generation and Exchange is implemented using modular arithmetic and exponentiation operations in Python.

### Python Libraries Used:
| Library | Purpose |
| --- | --- |
| socket | Network communication between doctor and patients |
| threading | Multi-threaded handling of multiple patient connections |
| random | Generation of random numbers for cryptographic operations |
| sympy | Prime number generation and GCD calculations |
| hashlib | Secure hash function implementation (SHA-256) |
| base64 | Encoding/decoding of binary data |
| time | Timestamp generation and verification |
| os | Random number generation for AES initialization vectors |
| Crypto.Cipher.AES | AES encryption for secure messaging |
| Crypto.Util.Padding | Padding functions for AES encryption |

## Some Important Functions and Their Purpose

| Function | Purpose |
| --- | --- |
| `generate_keys()` | Generates ElGamal key pairs (p, g, x, y) |
| `elgamal_sign(message, p, g, x)` | Creates an ElGamal digital signature |
| `elgamal_verify(message, signature, p, g, y)` | Verifies an ElGamal digital signature |
| `encrypt(m, y, p, g)` | Encrypts a message using the ElGamal cryptosystem |
| `decrypt(c1, c2, x, p)` | Decrypts a message using the ElGamal cryptosystem |
| `hash_function(data)` | Computes a SHA-256 hash of the provided data |
| `compute_global_hash()` | Generates a group key from all session keys |
| `handle_client(conn, addr)` | Manages the authentication process for a single patient |
| `message_input_thread()` | Enables the doctor to send broadcast messages |

## Security and Safety Considerations
- The system uses timestamp verification to prevent replay attacks
- Failed authentication attempts result in temporary blocking of the patient device
- All communication is encrypted using strong cryptographic algorithms
- The session key is never transmitted in plaintext
- Digital signatures ensure message integrity and authenticity
- For production use, larger cryptographic parameters should be used
- The implementation includes proper error handling for network and cryptographic operations
- All session keys are unique to each doctor-patient pair
- The group key combines all session keys, requiring successful authentication from all patients

## References
- ElGamal Digital signature generation: CRYPTOGRAPHY AND NETWORK SECURITY PRINCIPLES AND PRACTICE SEVENTH EDITION GLOBAL EDITION Chapter 13 page 424
- ElGamal cryptography procedure: Chapter 10 page 318
- Python Socket Programming: https://docs.python.org/3/library/socket.html

- PyCryptodome Documentation: https://pycryptodome.readthedocs.io/  
