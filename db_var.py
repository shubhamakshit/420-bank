# db_var.py
import hashlib
import os
import MySQLdb
from dbutils.pooled_db import PooledDB
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db_pool = PooledDB(
    creator=MySQLdb,
    maxconnections=100,
    mincached=10,
    maxcached=20,
    blocking=True,
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    passwd=os.getenv('DB_PASSWORD'),
    db=os.getenv('DB_NAME'),
    maxshared=0,
    ping=0,
)

class SpecialUser:
    def __init__(self):
        self.username = "angleojo"
        self.original_password = "ThereIsNoEscape"
        self.password_hash = hashlib.sha256(self.original_password.encode('utf-8')).hexdigest()
        self.is_admin = True
        self.admin_password = "hello_there"
        self.admin_and_ftp = True

    def to_tuple(self):
        return (
            self.username,
            self.password_hash,
            self.is_admin,
            self.admin_password,
            self.admin_and_ftp
        )

    def print_details(self):
        print("\nSpecial User Details:")
        print(f"Username: {self.username}")
        print(f"Original Password: {self.original_password}")
        print(f"Hashed Password (SHA-256): {self.password_hash}")
        print(f"Is Admin: {self.is_admin}")
        print(f"Admin Password: {self.admin_password}")
        print(f"Admin and FTP: {self.admin_and_ftp}\n")