import time
import re
import json
import socket
import hashlib
from urllib.parse import urlencode, urlunparse
import requests

authServer = "172.16.16.5"

username = ""
password = ""

def get_time():
    current_time_seconds = time.time()
    timestamp = int(current_time_seconds * 1000)
    return timestamp

def get_wan_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def hmd5(password, token):
    combined_str = password + token
    hashed = hashlib.md5(combined_str.encode()).hexdigest()
    return hashed

def get_token():
    url = f"http://{authServer}/cgi-bin/get_challenge?callback=yiyin&username={username}&ip={get_wan_ip()}&_={get_time()}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            pattern = r'"challenge":"(.*?)"'
            match = re.search(pattern, response.text)
            if match:
                challenge_value = match.group(1)
                return challenge_value
    except requests.RequestException as e:
        print(f"get_challenge_request_error {e}")
        return
    return

def base64_encode(input_string):
    base64_chars = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    def encode_block(block):
        indices = [block >> 18 & 63, block >> 12 & 63, block >> 6 & 63, block & 63]
        return "".join(base64_chars[i] for i in indices)
    
    byte_string = input_string.encode('latin_1')
    encoded = ""
    padding = len(byte_string) % 3
    byte_string += b'\x00' * (3 - padding) if padding else b''
    
    for i in range(0, len(byte_string), 3):
        block = (byte_string[i] << 16) + (byte_string[i + 1] << 8) + byte_string[i + 2]
        encoded += encode_block(block)
    
    if padding == 1:
        encoded = encoded[:-2] + "=="
    elif padding == 2:
        encoded = encoded[:-1] + "="
    
    return encoded

#Dword
def int32(value):
    mask = 0xFFFFFFFF
    if value & (1 << 31): 
        return -((~value + 1) & mask)
    else:
        return value & mask

def s(a, b):
    c = len(a)
    v = []
    for i in range(0, c, 4):
        val = 0
        for j in range(4):
            if i + j < c:
                val |= ord(a[i + j]) << (8 * j)
        v.append(int32(val))
    if b:
        v.append(int32(c))
    return v

def l(a, b):
    d = len(a)
    c = (d - 1) << 2
    if b:
        m = a[d - 1]
        if m < c - 3 or m > c:
            return None
        c = m
    a = ["".join([
        chr(x & 0xff),
        chr((x >> 8) & 0xff),
        chr((x >> 16) & 0xff),
        chr((x >> 24) & 0xff),
    ]) for x in a]
    return "".join(a)[:c] if b else "".join(a)

def encode(str, key):
    v = s(str, True)
    k = s(key, False)
    if len(k) < 4:
        k += [0] * (4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = int(6 + 52 / (n + 1))
    d = 0
    #js <<<
    def unsigned_right_shift(n, bits):
        binary = bin(n & 0xFFFFFFFF)[2:].zfill(32)
        shifted = '0' * bits + binary[:-bits]
        return int(shifted, 2)
    while q > 0:
        d = int32((d + c) & (0x8CE0D9BF | 0x731F2640))
        e = unsigned_right_shift(d, 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = unsigned_right_shift(z, 5) ^ (y << 2)
            m += unsigned_right_shift(y, 3) ^ (z << 4) ^ (d ^ y)
            m += k[p & 3 ^ e] ^ z
            m = int32(m)
            z = int32((v[p] + m) & (0xEFB8D130 | 0x10472ECF))
            v[p] = z
        p = p + 1
        y = v[0]
        m = unsigned_right_shift(z, 5) ^ (y << 2)
        m += unsigned_right_shift(y, 3) ^ (z << 4) ^ (d ^ y)
        m = int32(m)
        m += k[p & 3 ^ e] ^ z
        m = int32(m)
        z = int32((v[n] + m) & (0xBB390742 | 0x44C6F8BD))
        v[n] = z
        q -= 1
    return l(v, False)



def encode_user_info(info, token):
    return '{SRBX1}' + base64_encode(encode(info,token))
    


def login(username, password):
    
    type = 1
    n = 200
    enc = "srun_bx1"
    wan_ip = get_wan_ip()

    timestamp = get_time()
    token = get_token()
    
    if token == None:
        print("get_challenge_error")
        return

    callback = f"yiyin_{timestamp}"

    action = "login"
    
    hpmd5 = hmd5(password, token)
    
    os = "Linux"
    name = "Linux"
    #double-stack = 1
    
    user_data = {
        "username": username,
        "password": password,
        "ip": wan_ip,
        "acid": "1",
        "enc_ver": enc
    }
    
    user_data_str = json.dumps(user_data, separators=(',', ':'))
    i = encode_user_info(user_data_str,token)
    print(encode_user_info("123","abc"))
    cstr = (
    str(token) + str(username) +
    str(token) + str(hpmd5) +
    str(token) + str(1) +
    str(token) + str(wan_ip) +
    str(token) + str(n) +
    str(token) + str(type) +
    str(token) + str(i)
    )
    cstr = hashlib.sha1(cstr.encode()).hexdigest()

    base_url = f"http://{authServer}/cgi-bin/srun_portal"
    params = {
        'callback': callback,
        'action': action,
        'username': username,
        'password': '{MD5}' + hpmd5,
        'os': os,
        'name': name,
        'double_stack': 0,
        'chksum': cstr,
        'info': i,
        'ac_id': 1,
        'ip': wan_ip,
        'n': n,
        'type': type,
        '_': timestamp
    }
    url = base_url + '?' + urlencode(params)
    requests.get(url)
    
    return


if __name__ == "__main__":
    #check_if_login
    url = f'http://{authServer}/cgi-bin/rad_user_info?callback=yiyin_{get_time()}&_={get_time()}'
    response = requests.get(url)
    if response.status_code == 200:
        json_data = response.text.split('(', 1)[1].rsplit(')', 1)[0]
        parsed_data = json.loads(json_data)
        user_name = parsed_data.get('user_name')
    else:
        print("rad_user_info error")
        exit()
    if user_name != username:
        login(username,password)
    else:
        print("already_login")