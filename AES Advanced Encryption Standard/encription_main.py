def text_to_binary_padded(plaintext, padding_char='#'): # byte string
    while len(plaintext) % 16 != 0:
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

def binary_to_hex(binary_string): # debugging purpose
    hex_string = ''
    for i in range(0, len(binary_string), 4):
        nibble = binary_string[i:i+4]
        hex_digit = hex(int(nibble, 2))[2:]  # Convert to hex and remove '0x'
        hex_string += hex_digit.upper()
    return hex_string

def S_Box(index: int) -> int:
    S = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    return S[index]

def Inverse_S_Box(index: int) -> int:
    INV_S = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    return INV_S[index]

def g(last_32_bits: str, round_number: int) -> str:
    # Round constants for AES Key Expansion, 1 based indexing
    RCON = [ 
        0x00000000, 
        0x01000000, 
        0x02000000, 
        0x04000000, 
        0x08000000, 
        0x10000000, 
        0x20000000, 
        0x40000000, 
        0x80000000, 
        0x1B000000, 
        0x36000000
    ]

    # Rotate left by 8 bits
    rotated = last_32_bits[8:] + last_32_bits[:8]

    # Substitute bytes using S-Box
    substituted = ''
    for i in range(0, 32, 8):
        byte = rotated[i:i+8]
        index_s_box = int(byte, 2)
        substituted_byte = S_Box(index_s_box)
        substituted += format(substituted_byte, '08b')

    # XOR with round constant
    rcon_value = RCON[round_number] 
    rcon_binary = format(rcon_value, '032b')
    result = format(int(substituted, 2) ^ int(rcon_binary, 2), '032b')
    return result

def state_matrix_from_block(block: str):
    state = [[0]*4 for _ in range(4)]  # 4x4 matrix

    for col in range(4):
        for row in range(4):
            byte = block[(col * 32) + (row * 8):(col * 32) + (row * 8) + 8]
            state[row][col] = int(byte, 2)
    
    return state


def Sub_Bytes(state: str, opType: str):
    substituted = ''
    for i in range(0, 128, 8):
        byte = state[i:i+8]
        index_s_box = int(byte, 2)
        substituted_byte = S_Box(index_s_box) if opType == 'encrypt' else Inverse_S_Box(index_s_box)
        substituted += format(substituted_byte, '08b')

    return substituted

def Shift_Rows(state: str, opType: str):
    SM = state_matrix_from_block(state)
    if opType == 'encrypt':
        # Shift rows to the left
        for r in range(4):
            SM[r] = SM[r][r:] + SM[r][:r]
    else:
        # Shift rows to the right
        for r in range(4):
            if r == 0:
                SM[r] = SM[r]
            else:
                SM[r] = SM[r][-r:] + SM[r][:-r]

    result = ''
    for col in range(4):
        for row in range(4):
            result += format(SM[row][col], '08b')

    return result


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def Mix_Columns(block: str, opType: str):
    state = state_matrix_from_block(block)

    if opType == "encrypt":
        matrix = [
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]
        ]
    else:  # decrypt
        matrix = [
            [14, 11, 13, 9],
            [9, 14, 11, 13],
            [13, 9, 14, 11],
            [11, 13, 9, 14]
        ]
    
    new_state = [[0]*4 for _ in range(4)]

    for c in range(4):  # column-wise
        for r in range(4):
            new_state[r][c] = (
                gmul(state[0][c], matrix[r][0]) ^
                gmul(state[1][c], matrix[r][1]) ^
                gmul(state[2][c], matrix[r][2]) ^
                gmul(state[3][c], matrix[r][3])
            )

    # return new_state
    result = ''
    for col in range(4):
        for row in range(4):
            result += format(new_state[row][col], '08b')

    return result

def Add_Round_Key(state: str, round_key: str):
    result = ''
    for i in range(0, 128, 8):
        state_byte = state[i:i+8]
        key_byte = round_key[i:i+8]
        xor_byte = format(int(state_byte, 2) ^ int(key_byte, 2), '08b')
        result += xor_byte
    return result

def AES_Algorithm(message: str, subKeys128: list, opType: str):
    with open("aes_debug_log.txt", "a") as f:
        f.write(f"\n{'='*20} {opType.upper()} MODE {'='*20}\n")
        f.write(f"Input: {binary_to_hex(message)}\n\n")
        
        if opType == 'encrypt':
            start, end = 0, 10
        else:
            start, end = 10, 0
            
        # Initial Round
        result = Add_Round_Key(message, subKeys128[start])
        f.write(f"Initial Round Result: {binary_to_hex(result)}\n")

        # Main Rounds
        step = 1 if opType == 'encrypt' else -1

        for r_num in range(start + step, end, step):
            result = Sub_Bytes(result, opType)
            result = Shift_Rows(result, opType)
            if opType == 'encrypt':
                result = Mix_Columns(result, opType)
                result = Add_Round_Key(result, subKeys128[r_num])
            else:
                result = Add_Round_Key(result, subKeys128[r_num])
                result = Mix_Columns(result, opType)
            f.write(f"Round {r_num:02d} Result: {binary_to_hex(result)}\n")

        # Final Round
        result = Sub_Bytes(result, opType)
        result = Shift_Rows(result, opType) 
        final_key = subKeys128[10] if opType == 'encrypt' else subKeys128[0]
        result = Add_Round_Key(result, final_key)
        
        f.write(f"Final Round Result:   {binary_to_hex(result)}\n")
        
    return result
    
            

def encrypt(message: str, key: list):
    message_binary = text_to_binary_padded(message)
    block_size = 128
    blocks = [message_binary[i : i + block_size] for i in range(0, len(message_binary), block_size)]
    ciphertext = ""
    opType = 'encrypt'

    for block in blocks:
        ciphertext += AES_Algorithm(block, key, opType) # gurrented to be 128 bits

    return ciphertext


def decrypt(ciphertext: str, key: list):
    block_size = 128
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_binary = ""
    opType = 'decrypt'

    for block in blocks:
        plaintext_binary += AES_Algorithm(block, key, opType) # gurrented to be 128 bits
    
    return binary_to_text_unpadded(plaintext_binary)

def keyExpansion(cipher_key_text: str) -> list:
    cipher_key = text_to_binary_padded(cipher_key_text) # 128 bits
    round_keys = []  
    round_keys.append(cipher_key) # round key 0

    for i in range(1, 11):
        last_32_bits = round_keys[i-1][-32:]
        t = g(last_32_bits, i)  # g function

        new_round_key = ''
        for j in range(0, 128, 32):
            segment = round_keys[i-1][j:j+32]
            if j == 0:
                new_segment = format(int(segment, 2) ^ int(t, 2), '032b')
            else:
                prev_segment = new_round_key[j-32:j]
                new_segment = format(int(segment, 2) ^ int(prev_segment, 2), '032b')
            new_round_key += new_segment

        round_keys.append(new_round_key)

    return round_keys

def main():
    open("aes_debug_log.txt", "w").close()

    # Read plaintext
    with open("plaintext_sender.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()

    # Key
    cipher_key_text = "Thats my Kung Fu"
    round_keys = keyExpansion(cipher_key_text)
    """
    for idx, key in enumerate(round_keys):
        print(f"Round Key {idx}: {binary_to_hex(key)}")
    """
    
    # Encryption 
    ciphertext = encrypt(plaintext, round_keys)

    with open("ciphertext.txt", "w", encoding="utf-8") as f:
        f.write(ciphertext)
    
    # Decryption
    decrypted_text = decrypt(ciphertext, round_keys)

    with open("plaintext_receiver.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_text)


if __name__ == "__main__":
    main()