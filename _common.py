import winreg, hashlib, os
from winreg import OpenKey
from ctypes import windll

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
                "screen_size":str(windll.user32.GetSystemMetrics(0)) + ',' + str(windll.user32.GetSystemMetrics(1)),
                "set_disks":''.join(i for i in os.listdrives())}

        return info

    def gen_certificate(self, val:str):
        cr = Crypto()
        return cr.hash512(val, 'utf-8')