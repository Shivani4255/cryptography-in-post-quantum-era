# We need functions from the PyCryptodome library
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# --- Part 1: Normal RSA Encryption ---

# 1. Get a message to encrypt from the user
plaintext = input("Enter the secret message you want to encrypt with RSA: ").encode('utf-8')

# 2. Generate a 2048-bit RSA key pair
print("\n[*] Generating a 2048-bit RSA key pair...")
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# For demonstration, we'll print the keys. In real life, the private key is kept secret!
print("[+] RSA Public Key (n, e):", (public_key.n, public_key.e))
print("[+] RSA Private Key (d):", private_key.d)
print("-" * 20)

# 3. Encrypt the message with the public key
print("[*] Encrypting your message with the public key...")
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(plaintext)
print("[+] Encrypted message (ciphertext):", binascii.hexlify(ciphertext))
print("-" * 20)


# --- Part 2: The "Quantum" Attack Simulation ---

print("\n[!] --- SIMULATING QUANTUM ATTACK WITH SHOR'S ALGORITHM ---")
print("[!] An attacker has your public key (n, e) and the ciphertext.")
print("[!] They use a quantum computer to run Shor's algorithm on 'n'.")
print("[!] Shor's algorithm efficiently finds the prime factors of 'n'.")

# In a real attack, a quantum computer would FACTOR public_key.n to find p and q.
# We SIMULATE this by just using the p and q we already have from the key generation.
# This demonstrates the devastating consequence: if you can factor n, you can get d.
p = private_key.p
q = private_key.q
print(f"[!] Quantum Simulation SUCCESS: Factors found! p={p}, q={q}")

# Once the attacker has p and q, they can easily calculate the private key 'd'.
# We will use the full "stolen" key to decrypt the message.
stolen_private_key = private_key

print("[!] Attacker has now reconstructed the private key!")
print("-" * 20)


# 3. Attacker decrypts the message with the stolen private key
print("[*] Attacker is now decrypting your message with the stolen key...")
decipher = PKCS1_OAEP.new(stolen_private_key)
decrypted_message = decipher.decrypt(ciphertext)

print("\n" + "="*40)
print("[!] ATTACK SUCCESSFUL!")
print("[!] The attacker decrypted your secret message:")
print(f"[!] Decrypted Message: {decrypted_message.decode('utf-8')}")
print("[!] CONCLUSION: RSA IS NOT SECURE AGAINST A QUANTUM ATTACK.")
print("="*40)