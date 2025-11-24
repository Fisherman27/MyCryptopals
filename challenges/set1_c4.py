# 2025.11.14
# 任务：只有一行是由单字节异或加密的英文文本，其他都是随机的hex字符串，找出这一行并解密

def read_txt(file_path):
    '''读取txt文件（每一行是一个hex字符串），返回一个列表'''
    with open(file_path, 'r') as f:
        lines = f.readlines()
        lines = [line[:-1] for line in lines]  # 去掉每行末尾的换行符
    return lines

def hex_to_str(hex_string):
    '''将hex字符串转换为字符串'''
    bytes_data = bytes.fromhex(hex_string)
    return bytes_data.decode('utf-8', errors='ignore')

from set1_c3 import evaluate_plaintext,single_byte_xor
def _get_score(line):
    '''对line用所有可能的单字节异或进行解密，返回最高分数及对应的明文'''
    max_score = 0
    for i in range(256):
        plain_hex = single_byte_xor(line,i)
        score = evaluate_plaintext(plain_hex)
        if score > max_score:
            max_score = score
            max_plain_hex = plain_hex
    return max_score,hex_to_str(max_plain_hex)

# 利用 c3.py 里，统计每行文本的有效字符数，找到最长的一个
if __name__ == "__main__":
    lines = read_txt(r'MyCryptopals\set1\t4.txt')
    scores = {}
    plaintexts = {}
    for i,line in enumerate(lines):
        if len(line) % 2 != 0:
            line = line[:-1]  # 如果长度不是偶数，去掉最后一个字符
        score,plaintext = _get_score(line)
        scores[i] = score
        plaintexts[i] = plaintext
    max_index = max(scores, key=scores.get)
    print(f'最高分数的行号：{max_index}，分数：{scores[max_index]}，明文：{plaintexts[max_index]}')
