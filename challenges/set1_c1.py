# 2025.11.7
# 任务：将十六进制字符串转换为base64字符串

# base64：将原始二进制数据6位一组（2**6=64），每个6位对应一个base64字符
# 不足6位的用0填充
import base64
def hex_to_base64(hex_str):
    # 将输入十六进制转化为原始字节
    bytes_data = bytes.fromhex(hex_str)

    # 转换回十六进制
    # hex_data = bytes_data.hex() # '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 

    # 在原始字节上进行操作，转化为base64形式
    base64_data = base64.b64encode(bytes_data) # b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    # 将base64字节转化为字符串
    base64_str = base64_data.decode('utf-8') # 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    return base64_str


if __name__ == "__main__":
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_str = hex_to_base64(hex_str)
    print(base64_str) # 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    # 流程：
    # 1.  49276 --> 0100 1001 0010 0111 0110 ...
    # 2. 6位一组 --> 010010 010010 011101 ...
    # 3. 每6位对应一个base64字符 --> SSd ...



# 形如 b'...' ，表示字节字符串（bytes类型）
# 密码学操作都应该在  原始字节  级别进行，而不是在各种编码（e.g. ）的字符串表示形式上直接操作，
# 后者只是用于显示。