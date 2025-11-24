# 2025.11.14
# 任务：实验使用重复密钥的异或加密（Vigenère cipher）

def repeating_key_xor(plaintext_hex: str, key_hex: str) -> str:
    plaintext_hex = bytes.fromhex(plaintext_hex)
    key_hex = bytes.fromhex(key_hex)
    ciphertext_hex = []
    for i in range(len(plaintext_hex)):
        res = plaintext_hex[i] ^ key_hex[i%len(key_hex)]
        ciphertext_hex.append(res)
    return bytes(ciphertext_hex).hex()

if __name__ == '__main__':
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    plaintext_hex = plaintext.encode('utf-8').hex()
    key = 'ICE'
    key_hex = key.encode('utf-8').hex()
    c = repeating_key_xor(plaintext_hex, key_hex)
    print(f'Ciphertext 1: {c}')

