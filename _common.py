import random
import string
import winreg, hashlib, os
from winreg import OpenKey
from ctypes import windll
from string import printable
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

class Reg:
    def write_to(self,signature ,key=winreg.HKEY_CURRENT_USER, subkey='SOFTWARE\\Shabanov', v_name='Signature'):
        hkey = winreg.CreateKey(key, subkey)
        winreg.SetValueEx(hkey, v_name, 0, winreg.REG_SZ, signature)
        winreg.CloseKey(hkey)
    def read_from(self, key=winreg.HKEY_CURRENT_USER, subkey='SOFTWARE\\Shabanov\\', v_name = 'Signature'):
        try:
            op_key = OpenKey(key,subkey)
            return winreg.QueryValueEx(op_key, v_name)
        except FileNotFoundError:
            return [None]

class Crypto:
    def hash256(self, text:str, encoding:str):
        return hashlib.sha256(bytes(text, encoding=encoding)).hexdigest()

    def gen_key(self, length):
        symbl = printable[:95]
        key = ""
        for _ in range(length):
            key = key + symbl[random.randint(0,len(symbl))]

        return key

    def AESencrypt(self, text:str, key:bytes) -> str:
        cipher = AES.new(key, AES.MODE_ECB)
        enc = cipher.encrypt(bytes(text, encoding='utf-8'))
        return str(bytes_to_long(enc))

    def AESdecrypt(self, text:str, key:bytes)->str:
        #text:str - encode data 'bytes_in_long' -> 'bytes'
        byte_text = long_to_bytes(int(text))
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(byte_text)
        return str(dec, encoding='utf-8')

    def CryptoAPI(self, text:str, key:str, op:int, is_hash:bool=False) -> str|None:
        if len(key)!=16:
            exit(-1)
        key = bytes(key, encoding='utf-8')
        # Alignment
        if op==0:
            if len(text) % 16 != 0:
                text = text + ' ' * abs(16 - len(text) % 16)
            enc_t = self.AESencrypt(text, key)
            return enc_t

        elif op==1:
            text = self.AESdecrypt(text, key)
            return text.strip()

        else:
            return None

    def get_salt(self, passw_hash:str, delimiter='#'):
        p = passw_hash.split(delimiter)

        if len(p)==1:
            salt = p[0]
        else:
            salt = p[1]

        return salt

    def gen_salt(self, length):
        salt = ''
        chars = string.hexdigits
        for _ in range(length):
            salt = salt+chars[random.randint(0,len(chars)-1)]

        return salt

    def make_passwd(self, passw_str:str, n_salt:int):
        salt = self.gen_salt(n_salt)
        passw = passw_str + salt
        return self.hash256(passw,'utf-8')+'#'+salt

    def verify(self, passw:str, db_passw):
        salt = self.get_salt(db_passw)
        passw = passw+salt
        return self.hash256(passw,'utf-8')==db_passw.split('#')[0]


class Signature:
    def col_info(self):
        info = {"user":os.getlogin(),
                "computer_name":os.environ['COMPUTERNAME'],
                "win_path":os.environ['SystemRoot'],
                "sys_file_path":os.environ['SystemRoot'] + '\\System32',
                "type_keyboard":str(windll.user32.GetKeyboardType(0)),
                "sub_type":str(windll.user32.GetKeyboardType(1)),
                "width_screen":str(windll.user32.GetSystemMetrics(0)),
                "set_disks":''.join(i for i in os.listdrives())}

        return info

    def gen_key(self):
        keys = RSA.generate(1024)
        return keys

    def gen_cert(self, mess: str, pr_key: RSA.RsaKey):
        h = SHA256.new(bytes(mess, encoding='utf-8'))
        signature = pkcs1_15.new(pr_key).sign(h)
        return signature

    def verify(self, mess: str, pub_key: RSA.RsaKey, sign: bytes):
        h = SHA256.new(bytes(mess, encoding='utf-8'))
        try:
            pkcs1_15.new(pub_key).verify(h, sign)
            return 0
        except (ValueError, TypeError):
            return -1