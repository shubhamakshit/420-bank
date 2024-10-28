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

    def cleanup_database(self):
        """Clean up any existing tables and sequences"""
        self.cursor.execute("DROP TABLE IF EXISTS users_backup")
        self.cursor.execute("DROP TABLE IF EXISTS users")
        if self.db_type == 'postgresql':
            self.cursor.execute("DROP SEQUENCE IF EXISTS users_id_seq CASCADE")
        self.db.commit()
        logging.info("Database cleanup completed")

    def drop_and_create_table(self):
        """Drop and recreate the users table with database-agnostic syntax"""
        self.cleanup_database()

        if self.db_type == 'mysql':
            create_table_query = """
            CREATE TABLE users (
                id INTEGER AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                admin_password VARCHAR(255),
                admin_and_ftp BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status VARCHAR(10) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
                login_attempts INTEGER DEFAULT 0,
                CONSTRAINT admin_password_check CHECK ((is_admin = FALSE AND admin_password IS NULL) OR 
                                                     (is_admin = TRUE AND admin_password IS NOT NULL)),
                CONSTRAINT admin_ftp_check CHECK ((is_admin = TRUE AND admin_and_ftp IN (TRUE, FALSE)) OR 
                                                (is_admin = FALSE AND admin_and_ftp = FALSE))
            )
            """
        else:  # PostgreSQL
            create_table_query = """
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                admin_password VARCHAR(255),
                admin_and_ftp BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(10) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
                login_attempts INTEGER DEFAULT 0,
                CONSTRAINT admin_password_check CHECK ((is_admin = FALSE AND admin_password IS NULL) OR 
                                                     (is_admin = TRUE AND admin_password IS NOT NULL)),
                CONSTRAINT admin_ftp_check CHECK ((is_admin = TRUE AND admin_and_ftp IN (TRUE, FALSE)) OR 
                                                (is_admin = FALSE AND admin_and_ftp = FALSE))
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

    def generate_user_data(self) -> tuple:
        """Generate random user data with proper admin logic"""
        is_admin = self.fake.boolean(chance_of_getting_true=10)
        admin_password = self.fake.word()+ "_" + self.fake.word() if is_admin else None
        admin_and_ftp = self.fake.boolean(chance_of_getting_true=30) if is_admin else False

        return (
            self.fake.user_name(),
            hashlib.sha256(self.fake.password(length=10).encode('utf-8')).hexdigest(),
            is_admin,
            admin_password,
            admin_and_ftp,
            self.fake.random_element(elements=('active', 'inactive', 'suspended'))
        )

    def add_fake_data(self, num_users: int = 1302, special_user_id: Optional[int] = None):
        """Add fake data with database-agnostic syntax and proper user ordering"""
        if self.db_type == 'mysql':
            insert_query = """
            INSERT INTO users (username, password, is_admin, admin_password, admin_and_ftp, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
        else:
            insert_query = """
            INSERT INTO users (username, password, is_admin, admin_password, admin_and_ftp, status)
            VALUES %s
            """

        # Calculate how many users to insert before and after special user
        if special_user_id is not None:
            users_before = special_user_id - 1
            users_after = num_users - special_user_id
        else:
            users_before = num_users
            users_after = 0

        # Insert users before special user
        users_batch = []
        batch_size = 1000

        # Add users before special user
        for _ in tqdm(range(users_before), desc="Adding users before special user"):
            users_batch.append(self.generate_user_data())
            if len(users_batch) >= batch_size:
                self._insert_batch(insert_query, users_batch)
                users_batch = []

        if users_batch:
            self._insert_batch(insert_query, users_batch)
            users_batch = []

        # Insert special user if specified
        if special_user_id is not None:
            self._insert_special_user(special_user_id)

        # Add remaining users after special user
        for _ in tqdm(range(users_after), desc="Adding users after special user"):
            users_batch.append(self.generate_user_data())
            if len(users_batch) >= batch_size:
                self._insert_batch(insert_query, users_batch)
                users_batch = []

        if users_batch:
            self._insert_batch(insert_query, users_batch)

        logging.info(f"Added {num_users} users successfully")

    def _insert_special_user(self, special_user_id: int):
        """Handle special user insertion with proper ID handling"""
        logging.info(f"Inserting special user at position {special_user_id}")

        if self.db_type == 'postgresql':
            # For PostgreSQL, we need to manually set the ID
            self.cursor.execute("""
                INSERT INTO users (id, username, password, is_admin, admin_password, admin_and_ftp, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                special_user_id,
                self.special_user.username,
                self.special_user.password_hash,
                self.special_user.is_admin,
                self.special_user.admin_password,
                self.special_user.admin_and_ftp,
                'active'
            ))
            # Reset sequence to continue with correct IDs
            self.cursor.execute("SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))")
        else:
            # For MySQL, directly insert with ID
            self.cursor.execute("""
                INSERT INTO users (id, username, password, is_admin, admin_password, admin_and_ftp, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                special_user_id,
                self.special_user.username,
                self.special_user.password_hash,
                self.special_user.is_admin,
                self.special_user.admin_password,
                self.special_user.admin_and_ftp,
                'active'
            ))

        self.db.commit()
        self.special_user.print_details()

    def _insert_batch(self, insert_query: str, users_batch: List[tuple]):
        """Handle batch insertion for both MySQL and PostgreSQL"""
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

    def get_user_stats(self) -> dict:
        """Get statistics about users with database-agnostic syntax"""
        stats = {}

        # Total users
        self.cursor.execute("SELECT COUNT(*) FROM users")
        stats['total_users'] = self.cursor.fetchone()[0]

        # Admin users count
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")
        stats['admin_count'] = self.cursor.fetchone()[0]

        # Admin with FTP count
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE AND admin_and_ftp = TRUE")
        stats['admin_with_ftp_count'] = self.cursor.fetchone()[0]

        # Status distribution
        self.cursor.execute("""
            SELECT status, COUNT(*) 
            FROM users 
            GROUP BY status
        """)
        stats['status_distribution'] = dict(self.cursor.fetchall())

        # Verify special user position
        self.cursor.execute("SELECT MIN(id), MAX(id) FROM users")
        min_id, max_id = self.cursor.fetchone()
        stats['id_range'] = {'min': min_id, 'max': max_id}

        return stats

    def find_suspicious_users(self) -> List[tuple]:
        """Find potentially suspicious users with database-agnostic syntax"""
        query = """
        SELECT id, username, login_attempts, is_admin, admin_and_ftp
        FROM users 
        WHERE login_attempts > 5 
        OR (is_admin = TRUE AND admin_and_ftp = TRUE)
        ORDER BY id
        """
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def backup_table(self, backup_table_name: str):
        """Create a backup of the users table with database-agnostic syntax"""
        self.cursor.execute(f"DROP TABLE IF EXISTS {backup_table_name}")

        if self.db_type == 'mysql':
            self.cursor.execute(f"CREATE TABLE {backup_table_name} LIKE users")
            self.cursor.execute(f"INSERT INTO {backup_table_name} SELECT * FROM users")
        else:
            self.cursor.execute(f"CREATE TABLE {backup_table_name} AS SELECT * FROM users")

        self.db.commit()
        logging.info(f"Created backup table: {backup_table_name}")


def main():
    with DatabaseManager() as db_manager:
        # Initialize database
        db_manager.drop_and_create_table()

        # Add initial data with special user ID
        db_manager.add_fake_data(num_users=1302, special_user_id=950)

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