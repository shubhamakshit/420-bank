import MySQLdb
import psycopg2
from psycopg2 import extras
from faker import Faker
from tqdm import tqdm
import hashlib
from db_var import db_pool, SpecialUser
from typing import List, Union, Optional
import logging
from datetime import datetime
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=f'db_operations_{datetime.now().strftime("%Y%m%d")}.log'
)

class DatabaseManager:
    def __init__(self):
        self.db = db_pool.connection()
        self.cursor = self.db.cursor()
        self.special_user = SpecialUser()
        self.fake = Faker()
        self.db_type = os.getenv('DB_TYPE', 'mysql').lower()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.db.close()

    def drop_and_create_table(self):
        """Drop and recreate the users table with database-agnostic syntax"""
        self.cursor.execute("DROP TABLE IF EXISTS users")

        if self.db_type == 'mysql':
            create_table_query = """
            CREATE TABLE users (
                id INTEGER AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) DEFAULT NULL,
                password VARCHAR(255) DEFAULT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                admin_password VARCHAR(255) DEFAULT NULL,
                admin_and_ftp BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status VARCHAR(10) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
                login_attempts INTEGER DEFAULT 0
            )
            """
        else:  # PostgreSQL
            create_table_query = """
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) DEFAULT NULL,
                password VARCHAR(255) DEFAULT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                admin_password VARCHAR(255) DEFAULT NULL,
                admin_and_ftp BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(10) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
                login_attempts INTEGER DEFAULT 0
            )
            """
        self.cursor.execute(create_table_query)

        if self.db_type == 'postgresql':
            trigger_query = """
            CREATE OR REPLACE FUNCTION update_last_modified()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.last_modified = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS update_last_modified_trigger ON users;
            CREATE TRIGGER update_last_modified_trigger
                BEFORE UPDATE ON users
                FOR EACH ROW
                EXECUTE FUNCTION update_last_modified();
            """
            self.cursor.execute(trigger_query)

        self.db.commit()
        logging.info("Table created successfully")

    def add_fake_data(self, num_users: int = 1302, special_user_id: Optional[int] = None):
        """Add fake data with database-agnostic syntax"""
        if self.db_type == 'mysql':
            insert_query = """
            INSERT INTO users (id, username, password, is_admin, admin_password, admin_and_ftp, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
        else:
            # PostgreSQL: exclude id column as it's auto-generated
            insert_query = """
            INSERT INTO users (username, password, is_admin, admin_password, admin_and_ftp, status)
            VALUES %s
            """

        # Add special user with specific ID if provided
        if special_user_id:
            if self.db_type == 'postgresql':
                # For PostgreSQL, use sequence to set specific ID
                self.cursor.execute(f"ALTER SEQUENCE users_id_seq RESTART WITH {special_user_id}")
                special_data = (
                    self.special_user.username,
                    self.special_user.password_hash,
                    self.special_user.is_admin,
                    self.special_user.admin_password,
                    self.special_user.admin_and_ftp,
                    'active'
                )
                self.cursor.execute(
                    "INSERT INTO users (username, password, is_admin, admin_password, admin_and_ftp, status) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    special_data
                )
            else:
                special_user_data = list(self.special_user.to_tuple())
                special_user_data.insert(0, special_user_id)
                special_user_data.append('active')
                self.cursor.execute(insert_query, special_user_data)

            self.special_user.print_details()
            self.db.commit()
        else:
            logging.info(f"Not adding special user for {num_users} users")

        # Prepare batch insertion
        batch_size = 1000
        users_batch = []

        for _ in tqdm(range(num_users - 1), desc="Preparing users"):
            if self.db_type == 'mysql':
                user_data = [
                    None,  # ID (auto-increment)
                    self.fake.user_name(),
                    hashlib.sha256(self.fake.password(length=10).encode('utf-8')).hexdigest(),
                    self.fake.boolean(chance_of_getting_true=10),
                    self.fake.password(length=15) if self.fake.boolean(chance_of_getting_true=10) else None,
                    self.fake.boolean(chance_of_getting_true=5),
                    self.fake.random_element(elements=('active', 'inactive', 'suspended'))
                ]
            else:
                # PostgreSQL: exclude ID field
                user_data = (
                    self.fake.user_name(),
                    hashlib.sha256(self.fake.password(length=10).encode('utf-8')).hexdigest(),
                    self.fake.boolean(chance_of_getting_true=10),
                    self.fake.password(length=15) if self.fake.boolean(chance_of_getting_true=10) else None,
                    self.fake.boolean(chance_of_getting_true=5),
                    self.fake.random_element(elements=('active', 'inactive', 'suspended'))
                )
            users_batch.append(user_data)

            if len(users_batch) >= batch_size:
                if self.db_type == 'postgresql':
                    extras.execute_values(
                        self.cursor,
                        insert_query,
                        users_batch,
                        template="(%s, %s, %s, %s, %s, %s)"
                    )
                else:
                    self.cursor.executemany(insert_query, users_batch)
                self.db.commit()
                users_batch = []

        # Insert remaining users
        if users_batch:
            if self.db_type == 'postgresql':
                extras.execute_values(
                    self.cursor,
                    insert_query,
                    users_batch,
                    template="(%s, %s, %s, %s, %s, %s)"
                )
            else:
                self.cursor.executemany(insert_query, users_batch)
            self.db.commit()

        logging.info(f"Added {num_users} users successfully")

    def get_user_stats(self) -> dict:
        """Get statistics about users with database-agnostic syntax"""
        stats = {}

        # Total users
        self.cursor.execute("SELECT COUNT(*) FROM users")
        stats['total_users'] = self.cursor.fetchone()[0]

        # Admin users count
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")
        stats['admin_count'] = self.cursor.fetchone()[0]

        # Status distribution
        self.cursor.execute("""
            SELECT status, COUNT(*) 
            FROM users 
            GROUP BY status
        """)
        stats['status_distribution'] = dict(self.cursor.fetchall())

        return stats

    def find_suspicious_users(self) -> List[tuple]:
        """Find potentially suspicious users with database-agnostic syntax"""
        query = """
        SELECT id, username, login_attempts 
        FROM users 
        WHERE login_attempts > 5 
        OR (is_admin = TRUE AND admin_and_ftp = TRUE)
        """
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def backup_table(self, backup_table_name: str):
        """Create a backup of the users table with database-agnostic syntax"""
        if self.db_type == 'mysql':
            self.cursor.execute(f"CREATE TABLE {backup_table_name} LIKE users")
            self.cursor.execute(f"INSERT INTO {backup_table_name} SELECT * FROM users")
        else:
            # if PostgreSQL, and table exists already, drop it
            self.cursor.execute(f"DROP TABLE IF EXISTS {backup_table_name}")
            self.cursor.execute(f"CREATE TABLE {backup_table_name} AS SELECT * FROM users")

        self.db.commit()
        logging.info(f"Created backup table: {backup_table_name}")


def main():
    with DatabaseManager() as db_manager:
        # Initialize database
        db_manager.drop_and_create_table()

        # Add initial data with special user ID
        db_manager.add_fake_data(num_users=300, special_user_id=8)

        # Demonstrate some features
        print("\nCreating backup...")
        db_manager.backup_table('users_backup')

        print("\nGetting user stats...")
        stats = db_manager.get_user_stats()
        print("User Statistics:", stats)

        print("\nChecking for suspicious users...")
        suspicious = db_manager.find_suspicious_users()
        print(f"Found {len(suspicious)} suspicious users")

        print("Operations completed successfully.")

if __name__ == '__main__':
    main()