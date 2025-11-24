# 2025.11.24
# 任务：实现PKCS#7填充

def pkcs7_padding(text:bytes,block_size:int)->bytes:
    """
    输入原始字节串和块大小，返回PKCS#7填充后的字节串
    """
    padding_size = block_size - len(text) % block_size
    padding = bytes([padding_size]) * padding_size
    return text + padding

def pkcs7_unpadding(text:bytes)->bytes:
    """
    输入PKCS#7填充后的字节串，返回原始字节串
    """
    padding_size = text[-1]
    return text[:-padding_size]

if __name__ == '__main__':
    text = b'YELLOW SUBMARINE'
    block_size = 20
    padded_text = pkcs7_padding(text,block_size)
    print(padded_text)
