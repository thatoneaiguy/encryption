import hashlib
import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image

NUM_SALTS = 4
SALT_SIZE = 16
SALT_BAR_HEIGHT = 16
NUM_COLORS = 10
GRADIENT_WIDTH = 800
GRADIENT_HEIGHT = 100

def select_salt_index(width, height, color_sections, password_hash):
    combined = f"{width}-{height}-{color_sections}".encode() + password_hash
    digest = hashlib.sha256(combined).digest()
    return digest[0] % NUM_SALTS

def embed_salts(image, salts):
    width, _ = image.size
    bar_width = width // NUM_SALTS
    for i, salt in enumerate(salts):
        start_x = i * bar_width
        for byte_idx, byte in enumerate(salt):
            for bit_idx in range(8):
                bit = (byte >> (7 - bit_idx)) & 1
                px = start_x + (byte_idx * 8 + bit_idx) % bar_width
                py = (byte_idx * 8 + bit_idx) // bar_width
                if py >= SALT_BAR_HEIGHT:
                    raise ValueError("Salt too large for bar area")
                r, g, b = image.getpixel((px, py))
                b = (b & ~1) | bit
                image.putpixel((px, py), (r, g, b))

def extract_salts(image):
    width, _ = image.size
    bar_width = width // NUM_SALTS
    salts = []
    for i in range(NUM_SALTS):
        start_x = i * bar_width
        salt_bytes = []
        for byte_idx in range(SALT_SIZE):
            byte = 0
            for bit_idx in range(8):
                px = start_x + (byte_idx * 8 + bit_idx) % bar_width
                py = (byte_idx * 8 + bit_idx) // bar_width
                _, _, b = image.getpixel((px, py))
                bit = b & 1
                byte = (byte << 1) | bit
            salt_bytes.append(byte)
        salts.append(bytes(salt_bytes))
    return salts

def hash_text_with_salt(text, salt):
    return hashlib.pbkdf2_hmac('sha256', text.encode(), salt, 100_000)

def generate_colours(seed_hash, num_colours=10):
    return [
        (seed_hash[i * 3 % len(seed_hash)], seed_hash[(i * 3 + 1) % len(seed_hash)], seed_hash[(i * 3 + 2) % len(seed_hash)])
        for i in range(num_colours)
    ]

def create_gradient_image(colours, width=GRADIENT_WIDTH, height=GRADIENT_HEIGHT):
    img = Image.new('RGB', (width, height))
    num_sections = len(colours) - 1
    for x in range(width):
        section = int((x / width) * num_sections)
        factor = (x % (width // num_sections)) / (width // num_sections) if num_sections > 0 else 0
        c1, c2 = colours[section], colours[section + 1]
        r = int(c1[0] + (c2[0] - c1[0]) * factor)
        g = int(c1[1] + (c2[1] - c1[1]) * factor)
        b = int(c1[2] + (c2[2] - c1[2]) * factor)
        for y in range(height):
            img.putpixel((x, y), (r, g, b))
    return img

def embed_binary_data(image, seed_hash):
    binary = format(int.from_bytes(seed_hash[:4], 'big'), '032b')
    prng = random.Random(seed_hash)
    width, height = image.size
    positions = set()
    for bit in binary:
        while True:
            x = prng.randint(0, width - 1)
            y = prng.randint(SALT_BAR_HEIGHT, height - 1)
            if (x, y) not in positions:
                positions.add((x, y))
                break
        r, g, b = image.getpixel((x, y))
        b = (b | 1) if bit == '1' else (b & ~1)
        image.putpixel((x, y), (r, g, b))

def extract_binary_data(image, seed_hash):
    binary = ""
    prng = random.Random(seed_hash)
    width, height = image.size
    positions = set()
    for _ in range(32):
        while True:
            x = prng.randint(0, width - 1)
            y = prng.randint(SALT_BAR_HEIGHT, height - 1)
            if (x, y) not in positions:
                positions.add((x, y))
                break
        _, _, b = image.getpixel((x, y))
        binary += '1' if (b & 1) else '0'
    return binary

def derive_aes_key(binary_data):
    numeric_key = int(binary_data, 2)
    return hashlib.sha256(str(numeric_key).encode()).digest()

def encrypt_aes(plaintext: str, aes_key: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ct_bytes = cipher.encrypt(padded)
    return cipher.iv + ct_bytes

def decrypt_aes(ciphertext: bytes, aes_key: bytes) -> str:
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)
    return decrypted.decode('utf-8')

def generate_gradient_key_image(password, output_path):
    width = GRADIENT_WIDTH
    height = GRADIENT_HEIGHT
    num_colors = NUM_COLORS

    salts = [os.urandom(SALT_SIZE) for _ in range(NUM_SALTS)]
    dummy_hash = hashlib.sha256(password.encode()).digest()
    salt_index = select_salt_index(width, height, num_colors - 1, dummy_hash)
    real_salt = salts[salt_index]

    seed_hash = hash_text_with_salt(password, real_salt)
    colours = generate_colours(seed_hash, num_colors)
    img = create_gradient_image(colours, width, height)
    embed_salts(img, salts)
    embed_binary_data(img, seed_hash)
    img.save(output_path)
    print(f"Gradient key image saved as '{output_path}'")
    return img, seed_hash

def encrypt_text_to_file(plaintext: str, password: str, gradient_img_path: str, output_enc_path: str):
    img = Image.open(gradient_img_path)
    width, height = img.size

    dummy_hash = hashlib.sha256(password.encode()).digest()
    salts = extract_salts(img)
    salt_index = select_salt_index(width, height, NUM_COLORS - 1, dummy_hash)
    real_salt = salts[salt_index]

    seed_hash = hash_text_with_salt(password, real_salt)
    binary_key = extract_binary_data(img, seed_hash)
    aes_key = derive_aes_key(binary_key)

    encrypted_bytes = encrypt_aes(plaintext, aes_key)

    with open(output_enc_path, "wb") as f:
        f.write(encrypted_bytes)
    print(f"Encrypted message saved as '{output_enc_path}'")

def decrypt_text_from_file(gradient_img_path: str, password: str, encrypted_file_path: str) -> str:
    img = Image.open(gradient_img_path)
    width, height = img.size

    dummy_hash = hashlib.sha256(password.encode()).digest()
    salts = extract_salts(img)
    salt_index = select_salt_index(width, height, NUM_COLORS - 1, dummy_hash)
    real_salt = salts[salt_index]

    seed_hash = hash_text_with_salt(password, real_salt)
    binary_key = extract_binary_data(img, seed_hash)
    aes_key = derive_aes_key(binary_key)

    with open(encrypted_file_path, "rb") as f:
        encrypted_bytes = f.read()

    plaintext = decrypt_aes(encrypted_bytes, aes_key)
    return plaintext

if __name__ == "__main__":
    password = "cGFzc3dvcmQ="
    gradient_img_path = "gradient_output.png"
    encrypted_file_path = "encrypted_message.bin"
    plaintext = "fucking hell"

    generate_gradient_key_image(password, gradient_img_path)

    encrypt_text_to_file(plaintext, password, gradient_img_path, encrypted_file_path)

    decrypted_text = decrypt_text_from_file(gradient_img_path, password, encrypted_file_path)
    print("[✓] Decrypted text:")
    print(decrypted_text)
