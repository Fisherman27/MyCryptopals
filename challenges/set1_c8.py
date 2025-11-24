# 2025.11.19
# 任务：不依靠密钥，识别出哪一段使用了ACE_128_ECB模式加密
# 提示：ECB模式下，相同的明文块会被加密成相同的密文块，因此可以找有相同密文块的行

def split_into_128_blocks(bytes_hex:str,block_size:32)->list:
    """
    将字节串分割成多个128位块
    """
    return [bytes_hex[i:i+block_size] for i in range(0,len(bytes_hex),block_size)]

def check_the_same_block(blocks:list)->bool:
    """
    检查是否有相同的块
    """
    return len(blocks) != len(set(blocks))

if __name__ == '__main__':
    file_name = 't8.txt'
    with open(file_name,'r') as f:
        lines = f.readlines()
    lines = [line.strip() for line in lines]

    target_line = None
    target_blocks = None
    for line in lines:
        blocks = split_into_128_blocks(line,32)
        if check_the_same_block(blocks):
            print(f'找到含重复块的行：{line}')
            target_line = line
            target_blocks = blocks
