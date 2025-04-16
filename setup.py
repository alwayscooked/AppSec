import os,winreg,_common
from Crypto.Util.number import *

class Installer:
    def check_posgresql(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
            i = 0
            while True:
                subkey = winreg.EnumKey(key,i)
                if 'postgresql' in subkey.lower():
                    return True
                i+=1
        except:
            return False

    def check_requirements(self)->bool:
        if self.check_posgresql():
            return True
        return False

    def move(self, from_dir,to):
        try:
            with open(from_dir, 'rb') as fl:
                data = fl.read()
            with open(to,'wb') as fl:
                fl.write(data)
        except FileNotFoundError:
            return -1
        return 0

    def install_py_requirements(self):
        print("Встановлення залежностей...")
        try:
            os.system("pip install -r requirements.txt")
        except:
            exit(-1)

    def main(self, path = os.path.join(os.environ['USERPROFILE'], 'Documents'),
             files=('app.py','conf.toml'),app_dir='SimplePyApp', py_req:bool=True):

        if py_req:
            self.install_py_requirements()

        sign = _common.Signature()
        reg = _common.Reg()
        app_dir = os.path.join(path, app_dir)
        print(f"Створення {app_dir}")
        if os.path.exists(app_dir):
            print("Каталог вже встановлений")
        else:
            try:
                os.makedirs(app_dir)
            except Exception as e:
                print(e)
                exit(-1)

        for i in files:
            path_file = os.path.join(app_dir,i)
            if self.move(i,path_file)==-1:
                print("Не можемо знайти файл ", i)
                print("Скасування... ")
                return -1

        info = sign.col_info()
        info['current_vol'] = path.split('\\')[0]
        info = str(info)
        # gen keys
        keys = sign.gen_key()
        with open('pkey', 'wb') as fl:
            data = keys.public_key().exportKey()
            fl.write(data)

        #creation sign
        cert = str(bytes_to_long(sign.gen_cert(info,keys)))
        reg.write_to(cert)
        print("Залежності встановлено!")
        print("Встановлення закінчено!")
        return 0

if __name__=='__main__':
    start = Installer()
    if not start.check_posgresql():
        print("Please install Postgres DBMS!")
    new_path = input(f"Enter path(default {os.path.join(os.environ['USERPROFILE'])}\\Documents): ")
    if not new_path:
        start.main()
    else:
        start.main(path=new_path)