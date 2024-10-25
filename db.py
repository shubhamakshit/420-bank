import MySQLdb
from faker import Faker
from tqdm import tqdm
import hashlib
from db_var import db_pool, SpecialUser
from typing import List, Union, Optional
import logging
from datetime import datetime

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

    def drop_and_create_table(self):
        """Drop and recreate the users table with additional columns"""
        self.cursor.execute("DROP TABLE IF EXISTS users")

        create_table_query = """
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) DEFAULT NULL,
            password VARCHAR(255) DEFAULT NULL,
            is_admin TINYINT(1) DEFAULT NULL,
            admin_password VARCHAR(255) DEFAULT NULL,
            admin_and_ftp TINYINT(1) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
            login_attempts INT DEFAULT 0
        )
        """
        self.cursor.execute(create_table_query)
        self.db.commit()
        logging.info("Table created successfully")

    def add_fake_data(self, num_users: int = 1302, special_user_id: Optional[int] = None):
        """Add fake data with option to specify special user ID"""
        insert_query = """
        INSERT INTO users (id, username, password, is_admin, admin_password, admin_and_ftp, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        # Add special user with specific ID if provided
        special_user_data = list(self.special_user.to_tuple())
        if special_user_id:
            special_user_data.insert(0, special_user_id)
            special_user_data.append('active')  # Add status
            self.cursor.execute(insert_query, special_user_data)
            self.special_user.print_details()
        else:
            print(f"Not adding special user for {num_users} users")
            pass




        # Prepare batch insertion for better performance
        batch_size = 1000
        users_batch = []

        for _ in tqdm(range(num_users - 1), desc="Preparing users"):
            user_data = [
                None,  # ID (auto-increment)
                self.fake.user_name(),
                hashlib.sha256(self.fake.password(length=10).encode('utf-8')).hexdigest(),
                self.fake.boolean(chance_of_getting_true=10),
                self.fake.password(length=15) if self.fake.boolean(chance_of_getting_true=10) else None,
                self.fake.boolean(chance_of_getting_true=5),
                self.fake.random_element(elements=('active', 'inactive', 'suspended'))
            ]
            users_batch.append(user_data)

            if len(users_batch) >= batch_size:
                self.cursor.executemany(insert_query, users_batch)
                users_batch = []

        # Insert remaining users
        if users_batch:
            self.cursor.executemany(insert_query, users_batch)

        self.db.commit()
        logging.info(f"Added {num_users} users successfully")

    def append_data(self, num_users: int):
        """Append additional users to the existing table"""
        logging.info(f"Appending {num_users} users to the database")
        self.add_fake_data(num_users=num_users)

    def delete_users_by_range(self, start_id: int, end_id: int):
        """Delete users within a specified ID range"""
        delete_query = "DELETE FROM users WHERE id BETWEEN %s AND %s"
        self.cursor.execute(delete_query, (start_id, end_id))
        deleted_count = self.cursor.rowcount
        self.db.commit()
        logging.info(f"Deleted {deleted_count} users between IDs {start_id} and {end_id}")
        return deleted_count

    def update_special_user_id(self, new_id: int):
        """Update the ID of the special user"""
        update_query = "UPDATE users SET id = %s WHERE username = %s"
        self.cursor.execute(update_query, (new_id, self.special_user.username))
        self.db.commit()
        logging.info(f"Updated special user ID to {new_id}")

    def get_user_stats(self) -> dict:
        """Get statistics about users in the database"""
        stats = {}

        # Total users
        self.cursor.execute("SELECT COUNT(*) FROM users")
        stats['total_users'] = self.cursor.fetchone()[0]

        # Admin users count
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        stats['admin_count'] = self.cursor.fetchone()[0]

        # Status distribution
        self.cursor.execute("""
            SELECT status, COUNT(*) 
            FROM users 
            GROUP BY status
        """)
        stats['status_distribution'] = dict(self.cursor.fetchall())

        return stats

    def bulk_status_update(self, status: str, id_list: List[int]):
        """Update status for multiple users at once"""
        if status not in ['active', 'inactive', 'suspended']:
            raise ValueError("Invalid status value")

        update_query = "UPDATE users SET status = %s WHERE id IN ({})".format(
            ','.join(['%s'] * len(id_list))
        )
        self.cursor.execute(update_query, [status] + id_list)
        self.db.commit()
        logging.info(f"Updated status to {status} for {len(id_list)} users")

    def find_suspicious_users(self) -> List[tuple]:
        """Find potentially suspicious users based on various criteria"""
        query = """
        SELECT id, username, login_attempts 
        FROM users 
        WHERE login_attempts > 5 
        OR (is_admin = 1 AND admin_and_ftp = 1)
        """
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def backup_table(self, backup_table_name: str):
        """Create a backup of the users table"""
        self.cursor.execute(f"DROP TABLE IF EXISTS {backup_table_name}")
        self.cursor.execute(f"CREATE TABLE {backup_table_name} LIKE users")
        self.cursor.execute(f"INSERT INTO {backup_table_name} SELECT * FROM users")
        self.db.commit()
        logging.info(f"Created backup table: {backup_table_name}")

    def close_connection(self):
        """Close database connection"""
        self.cursor.close()
        self.db.close()
        logging.info("Database connection closed")

def main():
    db_manager = DatabaseManager()

    try:
        # Initialize database
        db_manager.drop_and_create_table()

        # Add initial data with special user ID
        db_manager.add_fake_data(num_users=1302, special_user_id=777)

        # Demonstrate some features
        print("\nCreating backup...")
        db_manager.backup_table('users_backup')

        print("\nGetting user stats...")
        stats = db_manager.get_user_stats()
        print("User Statistics:", stats)

        print("\nAppending more users...")
        db_manager.append_data(num_users=100)

        print("\nDeleting users in range...")
        deleted = db_manager.delete_users_by_range(10, 20)
        print(f"Deleted {deleted} users")

        print("\nChecking for suspicious users...")
        suspicious = db_manager.find_suspicious_users()
        print(f"Found {len(suspicious)} suspicious users")

        print("\nUpdating some user statuses...")
        db_manager.bulk_status_update('suspended', [1, 2, 3, 4, 5])

        print("Operations completed successfully.")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {str(e)}")
    finally:
        db_manager.close_connection()

if __name__ == '__main__':
    main()