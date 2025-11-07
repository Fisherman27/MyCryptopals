# 2025.11.7
# 任务：对输入的两个等长的十六进制字符串进行异或操作，输出十六进制的字符串

def fixed_xop(hex_str1,hex_str2):
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    # 必须进行逐位运算
    res_bytes = bytes([b1^b2 for b1,b2 in zip(bytes1,bytes2)])
    res_hex = res_bytes.hex() # str类型
    return res_hex

if __name__ == "__main__":
    hex_str1 = '1c0111001f010100061a024b53535009181c'
    hex_str2 = '686974207468652062756c6c277320657965'
    print(fixed_xop(hex_str1,hex_str2))

    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    print(bytes2)
    print(len(bytes2))
    print(bytes2[0])
    print(bytes1[0]^bytes2[0])

# print(bytes2) -->  b"hit the bull's eye" 是原始字节，但是为了可读性，显示成字符串的形式
# print(len(bytes2)) -->  18  字节的长度（1 bytes = 8 bits）
# print(bytes2[0]) -->  104  第一个字节的整数值( '0x68' --> 01101000 --> 104 ),int类型

# XOR操作(^) !!!必须在整数之间或者整数与Boolean值之间进行!!!
# 例如：
# # 整数之间
# print(65 ^ 42)         
# print(0b1010 ^ 0b1100) 
# # 整数与布尔值（True=1, False=0）
# print(65 ^ True)      
# print(65 ^ False)     