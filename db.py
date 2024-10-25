import MySQLdb
from faker import Faker
from tqdm import tqdm  # For showing progress bar
import hashlib

class Db:
    def __init__(self, host, user, password, database):
        # Connect to the MySQL database
        self.db = MySQLdb.connect(host, user, password, database)
        self.cursor = self.db.cursor()

    def drop_and_create_table(self):
        # Drop the existing users table if it exists
        self.cursor.execute("DROP TABLE IF EXISTS users")

        # Create the new users table
        create_table_query = """
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) DEFAULT NULL,
            password VARCHAR(255) DEFAULT NULL,
            is_admin TINYINT(1) DEFAULT NULL,
            admin_password VARCHAR(255) DEFAULT NULL,
            admin_and_ftp TINYINT(1) DEFAULT NULL
        )
        """
        self.cursor.execute(create_table_query)
        self.db.commit()

    def add_fake_data(self, num_users=1302):
        # Initialize Faker
        fake = Faker()

        # Insert fake users into the database
        insert_query = """
        INSERT INTO users (username, password, is_admin, admin_password, admin_and_ftp)
        VALUES (%s, %s, %s, %s, %s)
        """

        # Add the special entry
        special_username = "angleojo"
        original_password = "ThereIsNoEscape"
        special_password_hash = hashlib.sha256(original_password.encode('utf-8')).hexdigest()
        special_is_admin = True
        special_admin_password = "youAreA--' '-HackerMaybeYes##$%"
        special_admin_and_ftp = True
        self.cursor.execute(insert_query, (special_username, special_password_hash, special_is_admin, special_admin_password, special_admin_and_ftp))

        # Print details of the special user
        print("\nSpecial User Details:")
        print(f"Username: {special_username}")
        print(f"Original Password: {original_password}")
        print(f"Hashed Password (SHA-256): {special_password_hash}")
        print(f"Is Admin: {special_is_admin}")
        print(f"Admin Password: {special_admin_password}")
        print(f"Admin and FTP: {special_admin_and_ftp}\n")

        # Add the remaining users
        for _ in tqdm(range(num_users - 1), desc="Adding users"):
            # Generate fake data for the user
            username = fake.user_name()
            # Hash the password using SHA-256
            password_hash = hashlib.sha256(fake.password(length=10).encode('utf-8')).hexdigest()
            is_admin = fake.boolean(chance_of_getting_true=10)  # 10% chance of being an admin
            admin_password = fake.password(length=15) if is_admin else None
            admin_and_ftp = fake.boolean(chance_of_getting_true=5)  # 5% chance for admin_and_ftp being true

            # Insert the user data
            self.cursor.execute(insert_query, (username, password_hash, is_admin, admin_password, admin_and_ftp))

        # Commit the changes to the database
        self.db.commit()

    def close_connection(self):
        # Close the database connection
        self.cursor.close()
        self.db.close()


# Main code execution
if __name__ == '__main__':
    # Database connection parameters (replace with your own credentials)
    host = "172.23.98.94"
    user = "root"
    password = "akshit"
    database = "bank"

    # Create an instance of the Db class
    db = Db(host, user, password, database)

    try:
        # Drop the original table and recreate it
        db.drop_and_create_table()

        # Add 1302 new users to the table
        db.add_fake_data(num_users=1302)
        print("Users added successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        # Close the database connection
        db.close_connection()
