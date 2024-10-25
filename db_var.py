import hashlib
import os
import MySQLdb
import psycopg2  # Import for PostgreSQL support
from dbutils.pooled_db import PooledDB
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the database type from environment variables (default to MySQL if not specified)
db_type = os.getenv('DB_TYPE', 'mysql').lower()

# Configure the database connection pool based on the selected database type
if db_type == 'mysql':
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
elif db_type == 'postgresql':
    db_pool = PooledDB(
        creator=psycopg2,
        maxconnections=100,
        mincached=10,
        maxcached=20,
        blocking=True,
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        maxshared=0,
    )
else:
    raise ValueError("Unsupported DB_TYPE specified. Use 'mysql' or 'postgresql'.")

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