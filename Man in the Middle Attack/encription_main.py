import random

def diffie_hellman(p: int, g: int):
    private_key = random.randint(1, p-1)
    public_key = pow(g, private_key, p)
    return public_key, private_key


def encrypt(plaintext, key):
    encrypted = ""
    for char in plaintext:
        encrypted += chr((ord(char) + key) % 256)
    return encrypted

def decrypt(ciphertext, key):
    decrypted = ""
    for char in ciphertext:
        decrypted += chr((ord(char) - key) % 256)
    return decrypted

def main():
    # ===============================
    # Man in the Middle Attack demonstration in Diffie–Hellman Key Exchange
    # Alice will send message to Bob. Darth will intercept and read-write it.
    # ===============================
    p = 23  # A prime number
    g = 5   # A primitive root modulo p

    alice_public_key, alice_private_key = diffie_hellman(p, g)
    bob_public_key, bob_private_key = diffie_hellman(p, g)
    darth_public_key_alice, darth_private_key_alice = diffie_hellman(p, g) # to interact with Alice
    darth_public_key_bob, darth_private_key_bob = diffie_hellman(p, g)     # to interact with Bob

    # Private key should be kept secret by both parties

    # Secret key generation
    alice_secret_key = pow(darth_public_key_alice, alice_private_key, p)

    darth_secret_key_alice = pow(alice_public_key, darth_private_key_alice, p)
    darth_secret_key_bob = pow(bob_public_key, darth_private_key_bob, p)

    bob_secret_key = pow(darth_public_key_bob, bob_private_key, p)

    print("Alice Secret Key:", alice_secret_key)
    print("Darth Secret Key (Alice):", darth_secret_key_alice)
    print("Darth Secret Key (Bob):", darth_secret_key_bob)
    print("Bob Secret Key:", bob_secret_key)



    # ===============================
    # Alice encrypts & sends
    # ===============================
    with open("Alice_Inbox.txt", "r", encoding="utf-8") as f:
        plaintext1 = f.read()

    ciphertext1 = encrypt(plaintext1, alice_secret_key)




    # ===============================
    # Darth catches & reads
    # ===============================
    intercepted_text = decrypt(ciphertext1, darth_secret_key_alice)
    with open("Darth_Receiving.txt", "w", encoding="utf-8") as f:
        f.write(intercepted_text)

    # ===============================
    # Darth Modifys & sends
    # ===============================
    with open("Darth_Sending.txt", "r", encoding="utf-8") as f:
        plaintext2 = f.read()

    ciphertext2 = encrypt(plaintext2, darth_secret_key_bob)





    # ===============================
    # Bob receives & decrypts
    # ===============================
    decrypted_text = decrypt(ciphertext2, bob_secret_key)

    with open("Bob_Inbox.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_text)


if __name__ == "__main__":
    main()
