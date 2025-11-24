# 2025.11.19
# 任务：实现AES-128-ECB 解密 模式
# 所有函数的参数均应该为bytes类型，返回值也为bytes类型

# KEY = 'YELLOW SUBMARINE'
# KEY_bytes = b'YELLOW SUBMARINE'
# KEY_hex = KEY_bytes.hex()
# Nr = 10 # 轮数

RoundConstant = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,0x10000000, 
    0x20000000, 0x40000000, 0x80000000,0x1b000000, 0x36000000
]
# x = 0x20000000 x是int类型(可以直接进行位运算)
# x_bytes = x.to_bytes(4,'big')

SBox = [
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

invSBox = [
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

from set1_c6 import read_and_decode_cipher

def split_into_blocks(ciphertext_bytes:bytes,block_size:int=16)->list[bytes]:
    """
    将密文(bytes类型)，按block_size字节为一组，切分成长度为block_size的list
    """
    blocks = []
    for i in range(0,len(ciphertext_bytes),block_size):
        blocks.append(ciphertext_bytes[i:i+block_size])
    return blocks


class KeyExpansion:
    """
    AES密钥扩展器：将原始密钥扩展为加密/解密所需的所有轮密钥。 
    该类通过特定算法将原始密钥扩展为Nr+1组轮密钥，每个轮密钥为Nk字（4*Nk字节）。
    """
    def __init__(self,Nr:int=10,Nk:int=4):
        '''
        Nr: 轮数
        Nk: 密钥长度（字长）
        '''
        self.Nr = Nr
        self.Nk = Nk

    def __RotWord(self,word:bytes)->bytes:
        """
        将4字节的word循环左移1字节
        """
        return word[1:] + word[:1]

    def __SubWord(self,word:bytes)->bytes:
        """
        将4字节的word每个字节都用S-Box替换
        """
        return bytes([SBox[byte] for byte in word])
    
    def KeyExpand(self,key_bytes:bytes)->list[bytes]:
        """
        密钥扩展
        """
        w = [b'' for _ in range(4*(self.Nr+1))] # 需要 4*（Nr+1）个字
        i = 0
        # 先把key填充前四个字
        while i < self.Nk:
            w[i] = key_bytes[4*i:4*(i+1)]
            i += 1
        while i < 4*(self.Nr+1):
            temp = w[i-1]
            # if i%self.Nk == 0:
            #     temp = self.__SubWord(self.__RotWord(temp)) ^ RoundConstant[i//self.Nk]
            if i % self.Nk == 0:
                # 修正：RoundConstant转换为4字节bytes，再与temp异或
                rc = RoundConstant[i // self.Nk - 1].to_bytes(4, 'big')
                temp = self.__SubWord(self.__RotWord(temp))
                # 字节级异或（temp和rc均为4字节bytes）
                temp = bytes([t ^ r for t, r in zip(temp, rc)])
            elif self.Nk > 6 and i%self.Nk == 4:
                temp = self.__SubWord(temp)
            # w[i] = w[i-self.Nk] ^ temp
            # 修正：字节级异或（w[i-self.Nk]和temp均为4字节bytes）python不支持
            w[i] = bytes([a ^ b for a, b in zip(w[i-self.Nk], temp)])
            i += 1
        return w

class AES:
    """
    AES加密器：实现AES的加密/解密。
    """
    def __init__(self,key_bytes:bytes,Nr:int=10,Nk:int=4):
        '''
        Nr: 轮数
        Nk: 密钥长度（字长）
        '''
        # 验证明文长度是否和Nk,key_bytes长度匹配
        self.Nr = Nr
        self.Nk = Nk
        if len(key_bytes) != self.Nk*4:
            raise ValueError("密钥长度必须为Nk*4字节")
        self.key_bytes = key_bytes

        self.round_keys = KeyExpansion(Nr,Nk).KeyExpand(key_bytes)

    def __generate_state(self,text_bytes:bytes):
        """
        把text_bytes转化成state二维矩阵
        """
        self.state = [
            [text_bytes[col*4 + row] for col in range(4)]
            for row in range(4)
        ]
    
    def __SubBytes(self):
        for row in range(4):
            for col in range(4):
                self.state[row][col] = SBox[self.state[row][col]]

    def __InvSubBytes(self):
        for row in range(4):
            for col in range(4):
                self.state[row][col] = invSBox[self.state[row][col]]

    def __ShiftRows(self):
        for row in range(1,4):
            self.state[row] = self.state[row][row:] + self.state[row][:row]

    def __InvShiftRows(self):
        for row in range(1,4):
            self.state[row] = self.state[row][-row:] + self.state[row][:-row]

    def __galois_field_multiply(self,a:int,x:int)->int:
        """
        伽罗瓦域G(2^8)上的乘法
        """
        #从右至左观察a的每一位，进行相应的移位
        res = 0
        while a > 0:
            if a & 1: # 如果最后一位是1
                res ^= x
            x <<= 1
            if x & 0x100:
                x ^= 0x11b
            a >>= 1
        return res & 0xff # 只保留低8位
    
    def __mix_single_column(self,column:list[int])->list[int]:
        """
        对4字节的列进行列混合
        """
        new_column = [0 for i in range(4)]
        new_column[0] = self.__galois_field_multiply(2,column[0]) ^ self.__galois_field_multiply(3,column[1]) ^ column[2] ^ column[3]
        new_column[1] = column[0] ^ self.__galois_field_multiply(2,column[1]) ^ self.__galois_field_multiply(3,column[2]) ^ column[3]
        new_column[2] = column[0] ^ column[1] ^ self.__galois_field_multiply(2,column[2]) ^ self.__galois_field_multiply(3,column[3])
        new_column[3] = self.__galois_field_multiply(3,column[0]) ^ column[1] ^ column[2] ^ self.__galois_field_multiply(2,column[3])
        return new_column

    def __MixColumns(self):
        for col in range(4):
            column = [self.state[row][col] for row in range(4)]
            column = self.__mix_single_column(column)
            for row in range(4):
                self.state[row][col] = column[row]

    def __inv_mix_single_column(self,column:list[int])->list[int]:
        """
        对4字节的列进行逆列混合
        """
        new_column = [0 for i in range(4)]
        new_column[0] = self.__galois_field_multiply(0xe,column[0]) ^ self.__galois_field_multiply(0xb,column[1]) ^ self.__galois_field_multiply(0xd,column[2]) ^ self.__galois_field_multiply(0x9,column[3])
        new_column[1] = self.__galois_field_multiply(0x9,column[0]) ^ self.__galois_field_multiply(0xe,column[1]) ^ self.__galois_field_multiply(0xb,column[2]) ^ self.__galois_field_multiply(0xd,column[3])
        new_column[2] = self.__galois_field_multiply(0xd,column[0]) ^ self.__galois_field_multiply(0x9,column[1]) ^ self.__galois_field_multiply(0xe,column[2]) ^ self.__galois_field_multiply(0xb,column[3])
        new_column[3] = self.__galois_field_multiply(0xb,column[0]) ^ self.__galois_field_multiply(0xd,column[1]) ^ self.__galois_field_multiply(0x9,column[2]) ^ self.__galois_field_multiply(0xe,column[3])
        return new_column

    
    def __InvMixColumns(self):
        for col in range(4):
            column = [self.state[row][col] for row in range(4)]
            column = self.__inv_mix_single_column(column)
            for row in range(4):
                self.state[row][col] = column[row]

    def __AddRoundKey(self,roundk:int):
        '''
        roundk:第roundk轮
        '''
        key = self.round_keys[4*roundk:4*(roundk+1)] # 第roundk轮的轮密钥，有4个字（16个字节）
        for col in range(4):
            column = [self.state[row][col] for row in range(4)]
            # 对本列进行轮密钥加密
            w = key[col] # bytes
            column = [column[i] ^ w[i] for i in range(4)]
            # 写回state
            for row in range(4):
                self.state[row][col] = column[row]

    def encrypt(self,plaintext_bytes:bytes)->bytes:
        """
        加密,输出128字节的密文
        """
        if len(plaintext_bytes) != 16:
            raise ValueError("明文长度必须为16字节")
        self.__generate_state(plaintext_bytes)
        self.__AddRoundKey(roundk=0)
        #
        for round in range(1,self.Nr):
            self.__SubBytes()
            self.__ShiftRows()
            self.__MixColumns()
            self.__AddRoundKey(roundk=round)
        # 最后一轮
        self.__SubBytes()
        self.__ShiftRows()
        self.__AddRoundKey(roundk=self.Nr)
        # 把state转化成bytes
        ciphertext_bytes = bytes([self.state[row][col] for col in range(4) for row in range(4)])
        return ciphertext_bytes
    
    def decrypt(self,ciphertext_bytes:bytes)->bytes:
        """
        加密,输出128字节的密文
        """
        if len(ciphertext_bytes) != 16:
            raise ValueError("密文长度必须为16字节")
        self.__generate_state(ciphertext_bytes)
        self.__AddRoundKey(roundk=self.Nr)
        #
        for round in range(1,self.Nr):
            self.__InvShiftRows()
            self.__InvSubBytes()
            self.__AddRoundKey(roundk=self.Nr-round)
            self.__InvMixColumns()
        # 最后一轮
        self.__InvShiftRows()
        self.__InvSubBytes()
        self.__AddRoundKey(roundk=0)
        # 把state转化成bytes
        plaintext_bytes = bytes([self.state[row][col] for col in range(4) for row in range(4)])
        return plaintext_bytes
    
class AES_128_ECB:
    """
    AES-128-ECB加密器
    encrypt/ decrypt:可单独使用（需额外准备text（bytes））
    """
    def __init__(self,key_bytes:bytes,Nr:int=10,Nk:int=4):
        """
        初始化AES加密器
        """
        self.Nr = Nr
        self.Nk = Nk
        if len(key_bytes) != 4*self.Nk:
            raise ValueError(f"密钥长度必须为{4*self.Nk}字节")
        self.key_bytes = key_bytes
        self.aes = AES(self.key_bytes,self.Nr,self.Nk)


    def __split_into_blocks(self,text_bytes:bytes)->list[bytes]:
        """
        将字节串分割成16字节的块
        """
        blocks = [text_bytes[i:i+16] for i in range(0,len(text_bytes),16)]
        return blocks

    def encrypt(self,plaintext_bytes:bytes)->bytes:
        """
        加密,输出密文
        """
        blocks = self.__split_into_blocks(plaintext_bytes)
        ciphertext_blocks = []
        for block in blocks:
            ciphertext_block = self.aes.encrypt(block)
            ciphertext_blocks.append(ciphertext_block)
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext
    
    def decrypt(self,ciphertext_bytes:bytes)->bytes:
        """
        解密,输出明文
        """
        blocks = self.__split_into_blocks(ciphertext_bytes)
        plaintext_blocks = []
        for block in blocks:
            plaintext_block = self.aes.decrypt(block)
            plaintext_blocks.append(plaintext_block)
        plaintext = b''.join(plaintext_blocks)
        return plaintext
    
if __name__ == "__main__":
    key_bytes = b"YELLOW SUBMARINE"
    aes_128_ecb = AES_128_ECB(key_bytes,10,4)
    ciphertext_bytes = read_and_decode_cipher("t7.txt")
    plaintext_bytes = aes_128_ecb.decrypt(ciphertext_bytes)
    print(plaintext_bytes.decode())
