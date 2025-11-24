# 2025.11.24
# 任务：借助先前的AES-ECB实现CBC解密

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.append(root_dir)


from set1_c7 import AES
class AES_128_CBC:
    """
    AES-128-ECB加/解密器
    encrypt/ decrypt:可单独使用（需额外准备blocks(list[bytes])）
    """
    def __init__(self,key_bytes:bytes,IV :bytes,Nr:int=10,Nk:int=4):
        """
        初始化AES加密器
        """
        self.Nr = Nr
        self.Nk = Nk
        if len(key_bytes) != 4*self.Nk:
            raise ValueError(f"密钥长度必须为{4*self.Nk}字节")
        self.key_bytes = key_bytes
        self.IV = IV
        self.aes = AES(self.key_bytes,self.Nr,self.Nk)

    def __split_into_blocks(self,text_bytes:bytes)->list[bytes]:
        """
        将字节串分割成16字节的块
        """
        blocks = [text_bytes[i:i+16] for i in range(0,len(text_bytes),16)]
        return blocks

    def encrypt(self,plaintext_bytes:bytes)->bytes:
        """
        加密,输出128字节的密文
        """
        blocks = self.__split_into_blocks(plaintext_bytes)
        ciphertext_blocks = []
        for i in range(len(blocks)):
            if i == 0:
                temp = bytes([blocks[i][j] ^ self.IV[j] for j in range(16)])
            else:
                temp = bytes([blocks[i][j] ^ ciphertext_blocks[i-1][j] for j in range(16)])
            temp = self.aes.encrypt(temp)
            ciphertext_blocks.append(temp)
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext
    
    def decrypt(self,ciphertext_bytes:bytes)->bytes:
        """
        解密,输出128字节的明文
        """
        blocks = self.__split_into_blocks(ciphertext_bytes)
        plaintext_blocks = []
        for i in range(len(blocks)):
            temp = self.aes.decrypt(blocks[i])
            if i == 0:
                temp = bytes([temp[j] ^ self.IV[j] for j in range(16)])
            else:
                temp = bytes([temp[j] ^ blocks[i-1][j] for j in range(16)])
            plaintext_blocks.append(temp)
        plaintext = b''.join(plaintext_blocks)
        return plaintext

from set2_c9 import pkcs7_unpadding,pkcs7_padding
from set1_c6 import read_and_decode_cipher
if __name__ == '__main__':
    KEY = b'YELLOW SUBMARINE'
    BLOCK_SIZE = 16
    IV = b'\x01' * BLOCK_SIZE
    ciphertext_bytes = read_and_decode_cipher('t10.txt')
    aes_128_cbc = AES_128_CBC(KEY,IV)
    plaintext_bytes = aes_128_cbc.decrypt(ciphertext_bytes)
    plaintext_bytes = pkcs7_unpadding(plaintext_bytes)
    print(plaintext_bytes.decode())

    
