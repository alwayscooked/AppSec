import winreg, hashlib, os
from winreg import OpenKey
from ctypes import windll
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

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

    def hash512(self, text:str, encoding:str):
        return hashlib.sha512(bytes(text, encoding=encoding)).hexdigest()

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

    def gen_cert(self, mess:str, pr_key:RSA.RsaKey):
        h = SHA256.new(bytes(mess, encoding='utf-8'))
        signature = pkcs1_15.new(pr_key).sign(h)
        return signature

    def verify(self, mess:str, pub_key:RSA.RsaKey, sign:bytes):
        h = SHA256.new(bytes(mess, encoding='utf-8'))
        try:
            pkcs1_15.new(pub_key).verify(h, sign)
            return 0
        except (ValueError, TypeError):
            return -1