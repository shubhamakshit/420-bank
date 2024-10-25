from faker import Faker

# Initialize the Faker object
fake = Faker()

# Generate a username, password, and phone number
username = fake.user_name()
password = fake.password()
phone = fake.phone_number()

# Format the output as <username>:<password>:<phone>
output = f"{username}:{password}:{phone}"

print(output)

