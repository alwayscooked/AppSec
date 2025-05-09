import psycopg2, tomllib, _common, os
from tabulate import tabulate
from _common import Crypto


class Policy:
    def check_policy(self, password):
        return all(password[i] != password[i + 1] for i in range(len(password) - 1))

class DBClass:
    def __init__(self, dbname, user, password, host, port, session_key):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.key = session_key

    def request(self, command, args=None):
        try:
            with psycopg2.connect(database=self.dbname, user=self.user, password=self.password, port=self.port, host=self.host) as db:
                with db.cursor() as session:
                    session.execute(command, args or [])
                    return session.fetchall() if command.strip().lower().startswith('select') else None
        except psycopg2.Error as e:
            return e

    def create_init_table_if_not_exists(self):
        self.request('''CREATE TABLE IF NOT EXISTS users (
                username varchar(255) PRIMARY KEY,
                passw varchar(255),
                is_blocked boolean NOT NULL DEFAULT 'No',
                set_pass_policy boolean NOT NULL DEFAULT 'No');''')

    def init_values(self):
        hash_v = Crypto()
        init_username = hash_v.CryptoAPI('admin',self.key,0)
        init_admin_passw = hash_v.CryptoAPI(hash_v.hash256('', encoding='utf-8'),self.key,0)
        self.request("INSERT INTO users(username, passw) VALUES(%s, %s);",(init_username, init_admin_passw))

class Auth:
    def __init__(self, db:DBClass):
        self.db = db

    def identify(self, username):
        cr = Crypto()
        username = cr.CryptoAPI(username,self.db.key,0)
        return bool(self.db.request("SELECT 1 FROM users WHERE username=%s;", (username,)))

    def is_blocked(self, username):
        cr = Crypto()
        username = cr.CryptoAPI(username,self.db.key,0)
        result = self.db.request("SELECT is_blocked FROM users WHERE username=%s;", (username,))
        return result and result[0][0]

    def authenticate(self, username, password):
        hash_v = Crypto()
        username = hash_v.CryptoAPI(username,self.db.key,0)
        password = hash_v.CryptoAPI(hash_v.hash256(password, 'utf-8'), self.db.key, 0)
        result = self.db.request("SELECT passw FROM users WHERE username=%s;", (username,))
        return result and result[0][0] == password

class User:
    def __init__(self, username, password, db:DBClass):
        self.username = username
        self.password = password
        self.db = db
        self.cr = Crypto()

    def change_password(self):


        if input("Enter old password:") != self.password:
            print("Incorrect password!")
            return
        new_password = input("Enter new password:")


        username= self.cr.CryptoAPI(self.username,self.db.key,0)
        is_pass_policy = self.db.request("SELECT set_pass_policy FROM users WHERE username=%s;", (username,))
        pass_pol_obj = Policy() if is_pass_policy[0][0] else None
        if new_password == self.password:
            print("New password cannot be the same!")
            return

        if isinstance(pass_pol_obj,Policy):
            if not pass_pol_obj.check_policy(new_password):
                print("Password does not comply with password policy")
                return

        ack_passwd = input("Enter new password again:")
        if ack_passwd!=new_password:
            print("Entered password does not match with new password!")
            return

        self.cr = Crypto()
        self.db.request("UPDATE users SET passw=%s WHERE username=%s;", (
        self.cr.CryptoAPI(cr.hash256(new_password, 'utf-8'),self.db.key,0), username))
        self.password = new_password
        print("Password changed successfully!")

    def help(self):
        print("Commands: help, exit, passwd, info")

    def info(self):
        print("Author: student of group FB-21 Shabanov Kyrylo \n Individual task: 16. No consecutive identical characters.")

    def close(self):
        exit()

class Admin(User):
    def list_users(self):
        data = self.db.request("SELECT username, is_blocked, set_pass_policy FROM users;")
        data = [(self.cr.CryptoAPI(i[0],self.db.key,1),i[1],i[2]) for i in data]
        print(tabulate(data,headers=['Username', 'Blocked','PassPolicy']))

    def add_user(self):
        username = input("Enter username: ")
        if not Auth(self.db).identify(username):
            self.db.request("INSERT INTO users(username, passw) VALUES(%s, %s);",
                            (self.cr.CryptoAPI(username,self.db.key,0), self.cr.CryptoAPI(self.cr.hash256('', 'utf-8'),self.db.key,0),))
            print("User added successfully!")
        else:
            print("Username already taken!")

    def block_user(self):
        username = input("Enter username: ")
        if username=='admin':
            print("Admin cannot block himself!")
            return
        username = self.cr.CryptoAPI(username,self.db.key,0)
        request = self.db.request("SELECT is_blocked FROM users WHERE username=%s;", (username,))
        if request and request[0][0]==False:
            self.db.request("UPDATE users SET is_blocked = TRUE WHERE username=%s;", (username,))
            print("User blocked!")
        elif request and request[0][0]==True:
            self.db.request("UPDATE users SET is_blocked = FALSE WHERE username=%s;", (username,))
            print("User unblocked!")
        else:
            print("Unknown username!")

    def set_policy(self):
        username = input("Enter username: ")
        enc_username = self.cr.CryptoAPI(username,self.db.key,0)

        request = self.db.request("SELECT set_pass_policy FROM users WHERE username=%s;", (enc_username,))
        if request and request[0][0]==False:
            self.db.request("UPDATE users SET set_pass_policy = TRUE WHERE username=%s;", (enc_username,))
            print("Password policy set!")
        elif request and request[0][0]==True:
            self.db.request("UPDATE users SET set_pass_policy = FALSE WHERE username=%s;", (enc_username,))
            print(f"Password policy removed from {username} account!")
        else:
            print("Unknown username!")

    def help(self):
        print("Commands: help, exit, passwd, block, adduser, list_u, set_policy, info")

def main(db):
    num_att = 2
    auth = Auth(db)
    try:
        while num_att>-1:
            username = input("Enter username: ")
            password = input("Enter password: ")
            if auth.authenticate(username, password) and not auth.is_blocked(username):
                break
            print("Invalid credentials!")
            num_att-=1

        if num_att<0:
            return

        #Authorization
        user = Admin(username, password, db) if username == 'admin' else User(username, password, db)
        print("Welcome!")
        user.help()
        while True:
            cmd = input(f"{user.username}> ").strip().lower()
            if cmd == "passwd": user.change_password()
            elif cmd == "help": user.help()
            elif cmd == "info":user.info()
            elif cmd == "exit": user.close()
            elif isinstance(user, Admin) and cmd == "list_u": user.list_users()
            elif isinstance(user, Admin) and cmd == "adduser": user.add_user()
            elif isinstance(user, Admin) and cmd == "block": user.block_user()
            elif isinstance(user, Admin) and cmd == "set_policy": user.set_policy()
            else: print("Unknown command!")

    except KeyboardInterrupt:
        print("Exiting from interrupt!")
        exit(0)

if __name__ == '__main__':
    sign = _common.Signature()
    reg = _common.Reg()
    info = sign.col_info()
    info['current_vol'] = os.getcwd().split("\\")[0]
    if sign.gen_certificate(str(info))==reg.read_from()[0]:
        with open('conf.toml', 'rb') as tf:
            data = tomllib.load(tf)
        db_info = data['database']
        db = DBClass(db_info['name'], db_info['user'], db_info['password'], db_info['host'], db_info['port'], session_key=None)
        db.create_init_table_if_not_exists()
        if not db.request("select * from users;"):
            cr = Crypto()
            key = cr.gen_key(16)
            db.key = key
            print("Your db key(DON'T LOSE!):",key)
            db.init_values()
        else:
            key = input("Enter db key:")
            db.key = key
        main(db)

    else:
        print("An error occurred during execution.")