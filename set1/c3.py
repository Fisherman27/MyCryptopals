# 2025.11.7
# 任务：将一个由单字节密钥加密的密文破解

def single_byte_xor(cipher_hex:str,key:int):
    """
    用指定的密钥解密，返回明文（hex str)。
    （因为bytes[i]是int类型，所以key也必须是int类型）
    """
    cipher_bytes = bytes.fromhex(cipher_hex)
    plain_bytes = []
    for i in range(len(cipher_bytes)): # 逐字节进行异或
        plain_bytes.append(cipher_bytes[i]^key)
    plain_hex = bytes(plain_bytes).hex()
    return plain_hex



def evaluate_plaintext(plain_hex:str): # 原文本太短了，不适合统计频率，直接统计有效字符
    # 首先将十六进制转化
    plain_bytes = bytes.fromhex(plain_hex)

    # 在字节上统计字母频率，注意大小写
    valid_letters = 0
    for b in plain_bytes:
        if b >= 65 and b <= 90: # 大写字母
            valid_letters += 1
        elif b >= 97 and b <= 122: # 小写字母
            valid_letters += 1
        elif b == 32: # 空格
            valid_letters += 1
    return valid_letters


if __name__ == "__main__":
    cipher_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    best_score = float('-inf')
    best_key = None
    for key in range(256):
        plaintext = single_byte_xor(cipher_hex,key)
        score = evaluate_plaintext(plaintext)
        if score > best_score:
            best_score = score
            best_key = key
    print('Best Key:',best_key)
    best_plain = bytes.fromhex(single_byte_xor(cipher_hex,best_key))
    print('Decrypted Plaintext:',best_plain.decode('utf-8'))


# # \x后面跟着两位十六进制数，代表一个字节，
# # 例如：'\x42' 代表字节 0x42，即整数 66或b'B'



# # 2025.11.7
# # 任务：将一个由单字节密钥加密的密文破解

# def single_byte_xor(cipher_hex: str, key: int) -> str:
#     """
#     用指定的密钥解密，返回明文（hex str)。
#     """
#     cipher_bytes = bytes.fromhex(cipher_hex)
#     plain_bytes = bytes([b ^ key for b in cipher_bytes])
#     return plain_bytes.hex()


# def evaluate_plaintext(plain_hex: str) -> int:
#     """改进的评分函数：直接在字节层面评分，避免解码问题"""
#     try:
#         plain_bytes = bytes.fromhex(plain_hex)
        
#         # 包含空格和常见标点的频率统计
#         char_freq = {}
        
#         # 初始化频率字典（包含空格和字母）
#         for char in ' etaoinshrdlu':
#             char_freq[char] = 0
        
#         total_chars = 0
#         valid_letters = 0
        
#         for byte in plain_bytes:
#             # 处理大写字母（转换为小写统计）
#             if 65 <= byte <= 90:  # A-Z
#                 char = chr(byte + 32)  # 转换为小写
#                 if char in char_freq:
#                     char_freq[char] += 1
#                     valid_letters += 1
#                 total_chars += 1
            
#             # 处理小写字母
#             elif 97 <= byte <= 122:  # a-z
#                 char = chr(byte)
#                 if char in char_freq:
#                     char_freq[char] += 1
#                     valid_letters += 1
#                 total_chars += 1
            
#             # 处理空格
#             elif byte == 32:  # 空格
#                 char_freq[' '] += 1
#                 total_chars += 1
            
#             # 其他可打印字符（不统计但也不惩罚）
#             elif 33 <= byte <= 126:  # 可打印ASCII字符
#                 total_chars += 1
            
#             # 控制字符或非ASCII（严重惩罚）
#             else:
#                 total_chars += 1
#                 # 对非可打印字符进行惩罚
#                 return -100  # 直接返回很低的分
        
#         # 如果有效字符太少，分数降低
#         if total_chars == 0 or valid_letters / total_chars < 0.3:
#             return -50
        
#         # 按频率排序
#         sorted_freq = sorted(char_freq.items(), key=lambda x: x[1], reverse=True)
#         current_top = ''.join([char for char, freq in sorted_freq if freq > 0][:12])
        
#         # 标准频率顺序（包含空格）
#         standard_top = ' etaoinshrdl'
        
#         # 计算重合度（更合理的评分）
#         score = 0
#         for i, char in enumerate(current_top[:6]):  # 前6个最重要
#             if char in standard_top[:6]:
#                 score += 3 - i * 0.2  # 排名越靠前分数越高
        
#         for i, char in enumerate(current_top[6:12]):  # 后6个次要
#             if char in standard_top[6:12]:
#                 score += 1 - i * 0.1
        
#         return int(score * 10)  # 放大分数便于比较
        
#     except Exception as e:
#         return -1000  # 出现错误返回很低的分


# def safe_decode(byte_data):
#     """安全解码字节数据"""
#     try:
#         return byte_data.decode('utf-8', errors='ignore')
#     except:
#         return str(byte_data)  # 如果解码失败，返回字节表示


# if __name__ == "__main__":
#     cipher_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
#     best_score = float('-inf')
#     best_key = None
#     best_plain_hex = None
    
#     print("正在尝试所有可能的密钥...")
    
#     for key in range(256):
#         plaintext_hex = single_byte_xor(cipher_hex, key)
#         score = evaluate_plaintext(plaintext_hex)
        
#         # 显示有潜力的结果
#         if score > 0:
#             try:
#                 plain_text = safe_decode(bytes.fromhex(plaintext_hex))
#                 print(f"密钥 {key:3d} (ASCII: '{chr(key) if 32 <= key <= 126 else '?'}'): "
#                       f"分数: {score:4d} -> {plain_text}")
#             except:
#                 pass
        
#         if score > best_score:
#             best_score = score
#             best_key = key
#             best_plain_hex = plaintext_hex
    
#     print('\n' + '='*50)
#     print('最终破解结果:')
#     print('='*50)
    
#     best_plain_bytes = bytes.fromhex(best_plain_hex)
    
#     # 显示密钥信息
#     key_char = chr(best_key) if 32 <= best_key <= 126 else '非打印字符'
#     print(f'最佳密钥: {best_key} (十六进制: 0x{best_key:02x}, ASCII: "{key_char}")')
#     print(f'评分分数: {best_score}')
    
#     # 显示解密结果
#     print('\n解密结果:')
#     print(f'十六进制: {best_plain_hex}')
#     print(f'字节表示: {best_plain_bytes}')
#     print(f'文本内容: {safe_decode(best_plain_bytes)}')
    
#     # 验证可逆性
#     print('\n验证可逆性:')
#     encrypted_again = single_byte_xor(best_plain_hex, best_key)
#     print(f'重新加密后是否等于原密文: {encrypted_again == cipher_hex}')