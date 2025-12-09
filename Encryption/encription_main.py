def encrypt(message: str, mode: int):
    if mode == 1: # Caesar shift
        print("Enter Ceaser Key: ")
        key = int(input())
        result = ""

        for ch in message:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + key) % 26 + base)
            else:
                result += ch
        return result, key
    
    elif mode == 2: # Mono Alphabetic Substitution
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

        import random
        key_list = list(alphabet)
        random.shuffle(key_list)
        key = "".join(key_list)

        substitution_map = str.maketrans(alphabet, key)
        result = message.translate(substitution_map)
        return result, key
    
    elif mode == 3: # Columnar Transposition
        print("Enter Columnar Transposition Key (number of columns): ")
        key = int(input())
        row = len(message) // key + (len(message) % key > 0)
        matrix = [''] * row

        for r in range(row):
            for c in range(key):
                idx = r * key + c
                if idx < len(message):
                    matrix[r] += message[idx]
                else:
                    matrix[r] += '_'

        result = ''

        for c in range(key):
            for r in range(row):
                result += matrix[r][c]  
        return result, key


def decrypt(ciphertext: str, mode: int, key: int):
    
    if mode == 1: # Reverse Caesar shift
        result = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base - key) % 26 + base)
            else:
                result += ch
        return result
    
    elif mode == 2: # reverse Mono Alphabetic Substitution
        substitution_map = str.maketrans(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        result = ciphertext.translate(substitution_map)
        return result
    
    elif mode == 3:
        row = len(ciphertext) // key + (len(ciphertext) % key > 0)
        matrix = [''] * row

        for c in range(key):
            for r in range(row):
                idx = c * row + r
                matrix[r] += ciphertext[idx]

        for r in range(row):
            matrix[r] = matrix[r].replace('_', '')

        plaintext = ''.join(matrix)
        return plaintext
     
    else:
        raise ValueError("Invalid mode selected")


def main():
    with open("plaintext_sender.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()
    
    mode = 3   # Select encryption mode here: 1=Caesar, 2=Mono Alphabetic Substitution, 3. Collumnar Transposition
    
    ciphertext, key = encrypt(plaintext, mode)

    print(f"Encryption Key: {key}")

    with open("ciphertext.txt", "w", encoding="utf-8") as f:
        f.write(ciphertext)
    
    decrypted_text = decrypt(ciphertext, mode, key)

    with open("plaintext_receiver.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_text)


if __name__ == "__main__":
    main()
