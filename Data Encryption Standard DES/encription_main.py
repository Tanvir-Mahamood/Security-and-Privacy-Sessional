def text_to_binary_padded(plaintext, padding_char='#'):
    while len(plaintext) % 8 != 0:
        plaintext += padding_char
    
    binary_string = ''.join(format(ord(char), '08b') for char in plaintext)
    
    return binary_string

def binary_to_text_unpadded(binary_string, padding_char='#'):
    text_result = ""
    
    for i in range(0, len(binary_string), 8):
        byte_chunk = binary_string[i:i+8]
        
        char_code = int(byte_chunk, 2)
        text_result += chr(char_code)
        
    return text_result.rstrip(padding_char)

def subKeyGenerator(key64: str):
    pc1 = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]
    
    pc2 = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]
    
    permutation56 = ''.join([key64[i - 1] for i in pc1])

    C0 = permutation56[:28] # 28 bits
    D0 = permutation56[28:] # 28 bits

    C = [C0]
    D = [D0]

    for i in range(1, 17): # Calculating C1 to C16 and D1 to D16
        if i in [1, 2, 9, 16]:
            C_next = C[i-1][1:] + C[i-1][0]
            D_next = D[i-1][1:] + D[i-1][0]
        else:
            C_next = C[i-1][2:] + C[i-1][:2]
            D_next = D[i-1][2:] + D[i-1][:2]
        
        C.append(C_next)
        D.append(D_next)

    subKeys48 = [0] 
    for i in range(1, 17):
        CD = C[i] + D[i]
        subkey48 = ''.join([CD[j - 1] for j in pc2]) 
        subKeys48.append(subkey48)

    return subKeys48

def DES_Algorithm(message: str, subKeys48: list, opType: str):
    initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7]
    
    exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1]
    
    S_box = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],

        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],

        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],

        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],

        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],

        [   [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],

        [   [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],

        [   [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    P_box = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]
    
    final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]

    IP = ''.join([message[i - 1] for i in initial_perm]) # 64 bits

    L_32 = IP[:32] # L0 - 32 bits
    R_32 = IP[32:] # R0 - 32 bits

    start, stop, step = (1, 17, 1) if opType == "encrypt" else (16, 0, -1)

    for iter in range(start, stop, step): # 16 rounds
        R_expanded = ''.join([R_32[i - 1] for i in exp_d]) # 48 bits
        xor_result = bin(int(R_expanded, 2) ^ int(subKeys48[iter], 2))[2:].zfill(48) # 48 bits

        # S-boxes, converting 48 bits to 32 bits would go here (omitted for brevity)
        block_size = 6
        sbox_output = '' # 32 bits
        for i in range(8):
            block = xor_result[i*block_size:(i+1)*block_size]   
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            # print(f"S-box {i+1}, Row: {row}, Col: {col} Val={S_box[i][row][col]}")
            SB = S_box[i][row][col]
            sbox_output += bin(SB)[2:].zfill(4) # 4 bits

    
        # P-box permutation would go here (omitted for brevity)
        pbox_permuted = ''.join([sbox_output[i - 1] for i in P_box]) # 32 bits


        # Final XOR and swap
        R_new = bin(int(L_32, 2) ^ int(pbox_permuted, 2))[2:].zfill(32) # 32 bits
        L_new = R_32

        L_32 = L_new
        R_32 = R_new

    # Combine L16 and R16 and apply final permutation (omitted for brevity)
    preoutput = R_32 + L_32  # swap here

    ciphertext = ''.join([preoutput[i - 1] for i in final_perm]) # 64 bits
    return ciphertext
            

def encrypt(message: str, key: int):
    message_binary = text_to_binary_padded(message)
    block_size = 64
    blocks = [message_binary[i : i + block_size] for i in range(0, len(message_binary), block_size)]
    ciphertext = ""
    opType = 'encrypt'

    for block in blocks:
        ciphertext += DES_Algorithm(block, key, opType) # gurrented to be 64 bits

    return ciphertext


def decrypt(ciphertext: str, key: int):
    block_size = 64
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_binary = ""
    opType = 'decrypt'

    for block in blocks:
        plaintext_binary += DES_Algorithm(block, key, opType) # gurrented to be 64 bits
    return binary_to_text_unpadded(plaintext_binary)


def main():
    with open("plaintext_sender.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()
    
    key64 = "133457799BBCDFF1" # In hexadecimal, must have 16 hex digits = 64 bits
    decimal_key64 = int(key64, 16)
    binary_key64 = bin(decimal_key64)[2:].zfill(64)
    subKeys48 = subKeyGenerator(binary_key64) # K1 to K16
    
    
    ciphertext = encrypt(plaintext, subKeys48)

    with open("ciphertext.txt", "w", encoding="utf-8") as f:
        f.write(ciphertext)
    
    
    decrypted_text = decrypt(ciphertext, subKeys48)

    with open("plaintext_receiver.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_text)


if __name__ == "__main__":
    main()
