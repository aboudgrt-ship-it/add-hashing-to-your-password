import hashlib 
import secrets 
import base64 
import hmac 
#first we will create a function to generate a password hash using PBKDF2 with SHA-256. This function will take a password as input, generate a random salt, and return the hashed password in a specific format.

def generate_password_hash(password: str) -> str: 
    salt = secrets.token_bytes(16)
    password_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256' , password_bytes , salt , 200_000 , dklen=32)
    salt_664 = base64.urlsafe_b64encode(salt).decode('utf-8')
    key_664 = base64.urlsafe_b64encode(key).decode('utf-8')
    return f"200_000${salt_664}${key_664}"

# Next, we will create a function to verify the password hash. This function will take the stored password hash and the input password, extract the salt and key from the stored hash, and compare the generated key with the expected key using a constant-time comparison to prevent timing attacks.

def verify_password_hash(password: str) -> str:
    try:
        iterations_str , salt_664 , key_664 = password.split('$')
        iterations = int(iterations_str)
        salt = base64.urlsafe_b64decode(salt_664.encode('utf-8'))
        expected_key = base64.urlsafe_b64decode(key_664.encode('utf-8'))

# Generate the key from the input password and compare it with the expected key

        password_bytes = password.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256' , password_bytes , salt , iterations , dklen=32)
        return hmac.compare_digest(key , expected_key)
    
# If any error occurs during the verification process, we will catch the exception and return False to indicate that the password verification failed.

    except Exception as e:
        print(f"Error verifying password hash: {e}")
        return False
# Just for a little example 
password = "my_secure_password"
stored = generate_password_hash(password)
print(f"Stored password hash: {stored}")
is_valid = verify_password_hash(stored)
print(f"Password verification result: {is_valid}")

# THANKS :p