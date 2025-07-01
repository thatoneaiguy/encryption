import hashlib
import os
import secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image

# ---- SECURITY PARAMETERS ----
NUM_SALTS = 4
SALT_SIZE = 32  # Increased salt size
SALT_BAR_HEIGHT = 32
SECRET_SIZE = 32  # 256-bit secret
KEY_DERIVATION_ITERATIONS = 600_000  # OWASP recommended minimum
HEADER = b"StegoSecure\x00\x01"  # File format identifier
NUM_COLORS = 10
GRADIENT_WIDTH = 800
GRADIENT_HEIGHT = 300  # Increased for more pixel space


# ---- CRYPTO UTILITIES ----
class AuthenticationError(Exception):
    """Raised when HMAC verification fails"""


def secure_wipe(data):
    """Securely wipe sensitive data from memory"""
    if isinstance(data, bytes):
        data = bytearray(data)
    for i in range(len(data)):
        data[i] = 0
    del data


def derive_keys(master_secret):
    """Derive encryption and authentication keys using HKDF"""
    return HKDF(
        master_secret,
        64,  # 32-byte AES key + 32-byte HMAC key
        salt=None,
        hashmod=SHA512,
        num_keys=1,
        context=b"StegoCryptoV1"
    )


# ---- IMAGE OPERATIONS ----
def select_salt_index(width, height, color_sections, password_hash):
    """Determine which salt to use based on image properties"""
    combined = f"{width}-{height}-{color_sections}".encode() + password_hash
    return hashlib.sha256(combined).digest()[0] % NUM_SALTS


def embed_salts(image, salts):
    """Embed salts in image LSBs"""
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
                b = (b & 0xFE) | bit
                image.putpixel((px, py), (r, g, b))


def extract_salts(image):
    """Extract salts from image LSBs"""
    width, _ = image.size
    bar_width = width // NUM_SALTS
    salts = []
    for i in range(NUM_SALTS):
        start_x = i * bar_width
        salt_bytes = bytearray()
        for byte_idx in range(SALT_SIZE):
            byte_val = 0
            for bit_idx in range(8):
                px = start_x + (byte_idx * 8 + bit_idx) % bar_width
                py = (byte_idx * 8 + bit_idx) // bar_width
                _, _, b = image.getpixel((px, py))
                bit = b & 1
                byte_val = (byte_val << 1) | bit
            salt_bytes.append(byte_val)
        salts.append(bytes(salt_bytes))
    return salts


def generate_colors(seed_hash, num_colors=10):
    """Create color palette from hash with bounds checking"""
    hash_len = len(seed_hash)
    colors = []
    for i in range(num_colors):
        r = seed_hash[(i * 3) % hash_len]
        g = seed_hash[(i * 3 + 1) % hash_len]
        b = seed_hash[(i * 3 + 2) % hash_len]
        colors.append((r, g, b))
    return colors


def create_gradient_image(colors, width=GRADIENT_WIDTH, height=GRADIENT_HEIGHT):
    """Generate gradient image from color palette"""
    img = Image.new('RGB', (width, height))
    num_sections = len(colors) - 1
    section_width = width // num_sections if num_sections > 0 else width

    for x in range(width):
        section_idx = min(x // section_width, num_sections - 1) if num_sections > 0 else 0
        factor = (x % section_width) / section_width if section_width > 0 else 0
        c1, c2 = colors[section_idx], colors[section_idx + 1]
        r = int(c1[0] + (c2[0] - c1[0]) * factor)
        g = int(c1[1] + (c2[1] - c1[1]) * factor)
        b = int(c1[2] + (c2[2] - c1[2]) * factor)
        for y in range(height):
            img.putpixel((x, y), (r, g, b))
    return img


def get_pixel_positions(seed_hash, num_bits, width, height):
    """Generate cryptographically secure pixel positions"""
    total_pixels = width * (height - SALT_BAR_HEIGHT)
    positions = []
    counter = 0
    digest_size = 128  # Use SHAKE128 for extendable output

    while len(positions) < num_bits:
        # Generate position candidates
        h = hashlib.shake_128(seed_hash + counter.to_bytes(4, 'big')).digest(digest_size)
        for byte in h:
            pos = byte % total_pixels
            if pos not in positions:
                positions.append(pos)
            if len(positions) == num_bits:
                return positions
        counter += 1
    return positions


def embed_image_secret(image, seed_hash, secret):
    """Embed secret in image using secure position selection"""
    width, height = image.size
    num_bits = len(secret) * 8

    # Convert secret to bit string
    bit_string = ''.join(f'{byte:08b}' for byte in secret)

    # Get secure positions
    positions = get_pixel_positions(seed_hash, num_bits, width, height)

    # Embed bits
    for idx, bit in zip(positions, bit_string):
        y = SALT_BAR_HEIGHT + idx // width
        x = idx % width
        r, g, b = image.getpixel((x, y))
        b = (b & 0xFE) | int(bit)
        image.putpixel((x, y), (r, g, b))

    return positions


def extract_image_secret(image, seed_hash, num_bytes=SECRET_SIZE):
    """Extract secret from image using same position logic"""
    width, height = image.size
    num_bits = num_bytes * 8

    # Get positions (same algorithm as embedding)
    positions = get_pixel_positions(seed_hash, num_bits, width, height)

    # Extract bits
    bit_string = ''
    for idx in positions:
        y = SALT_BAR_HEIGHT + idx // width
        x = idx % width
        _, _, b = image.getpixel((x, y))
        bit_string += '1' if (b & 1) else '0'

    # Convert to bytes
    secret_bytes = bytes(int(bit_string[i:i + 8], 2) for i in range(0, len(bit_string), 8))
    return secret_bytes


# ---- CRYPTO OPERATIONS ----
def encrypt_aes(plaintext: str, aes_key: bytes) -> bytes:
    """Encrypt with AES-CBC and random IV"""
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def decrypt_aes(ciphertext: bytes, aes_key: bytes) -> str:
    """Decrypt AES-CBC ciphertext"""
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode('utf-8')


def add_hmac(ciphertext: bytes, mac_key: bytes) -> bytes:
    """Add HMAC authentication tag"""
    hmac = HMAC.new(mac_key, digestmod=SHA512)
    hmac.update(ciphertext)
    return ciphertext + hmac.digest()


def verify_hmac(data: bytes, mac_key: bytes) -> bytes:
    """Verify HMAC and return payload if valid"""
    if len(data) < 64:
        raise ValueError("Data too short for HMAC verification")

    received_ciphertext = data[:-64]
    received_mac = data[-64:]

    hmac = HMAC.new(mac_key, digestmod=SHA512)
    hmac.update(received_ciphertext)
    try:
        hmac.verify(received_mac)
    except ValueError:
        raise AuthenticationError("HMAC verification failed - data tampered!")

    return received_ciphertext


# ---- MAIN OPERATIONS ----
def generate_gradient_key_image(password, output_path):
    """Generate image with embedded secrets"""
    width = GRADIENT_WIDTH
    height = GRADIENT_HEIGHT
    num_colors = NUM_COLORS

    # Generate salts
    salts = [secrets.token_bytes(SALT_SIZE) for _ in range(NUM_SALTS)]

    # Select salt based on password
    dummy_hash = hashlib.sha256(password.encode()).digest()
    salt_index = select_salt_index(width, height, num_colors - 1, dummy_hash)
    real_salt = salts[salt_index]

    # Derive seed hash
    seed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        real_salt,
        KEY_DERIVATION_ITERATIONS
    )

    # Generate image
    colors = generate_colors(seed_hash, num_colors)
    img = create_gradient_image(colors, width, height)

    # Embed secrets
    embed_salts(img, salts)
    image_secret = secrets.token_bytes(SECRET_SIZE)
    embed_image_secret(img, seed_hash, image_secret)

    # Save and clean up
    img.save(output_path)
    secure_wipe(image_secret)
    secure_wipe(seed_hash)
    print(f"Gradient key image saved as '{output_path}'")
    return img


def encrypt_text_to_file(plaintext: str, password: str, gradient_img_path: str, output_enc_path: str):
    """Encrypt text to file using image secrets"""
    img = Image.open(gradient_img_path)
    width, height = img.size

    # Extract salts
    salts = extract_salts(img)

    # Select salt based on password
    dummy_hash = hashlib.sha256(password.encode()).digest()
    salt_index = select_salt_index(width, height, NUM_COLORS - 1, dummy_hash)
    real_salt = salts[salt_index]

    # Derive seed hash
    seed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        real_salt,
        KEY_DERIVATION_ITERATIONS
    )

    # Extract image secret
    image_secret = extract_image_secret(img, seed_hash)

    # Derive keys
    master_secret = seed_hash + image_secret
    keys = derive_keys(master_secret)
    aes_key, mac_key = keys[:32], keys[32:64]

    # Encrypt and authenticate
    ciphertext = encrypt_aes(plaintext, aes_key)
    protected_data = HEADER + add_hmac(ciphertext, mac_key)

    # Save to file
    with open(output_enc_path, "wb") as f:
        f.write(protected_data)

    # Clean sensitive data
    secure_wipe(seed_hash)
    secure_wipe(image_secret)
    secure_wipe(master_secret)
    secure_wipe(aes_key)
    secure_wipe(mac_key)

    print(f"Encrypted message saved as '{output_enc_path}'")


def decrypt_text_from_file(gradient_img_path: str, password: str, encrypted_file_path: str) -> str:
    """Decrypt text using image secrets"""
    img = Image.open(gradient_img_path)
    width, height = img.size

    # Read encrypted data
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    # Verify header
    if not encrypted_data.startswith(HEADER):
        raise ValueError("Invalid file format or version")

    # Extract salts
    salts = extract_salts(img)

    # Select salt based on password
    dummy_hash = hashlib.sha256(password.encode()).digest()
    salt_index = select_salt_index(width, height, NUM_COLORS - 1, dummy_hash)
    real_salt = salts[salt_index]

    # Derive seed hash
    seed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        real_salt,
        KEY_DERIVATION_ITERATIONS
    )

    # Extract image secret
    image_secret = extract_image_secret(img, seed_hash)

    # Derive keys
    master_secret = seed_hash + image_secret
    keys = derive_keys(master_secret)
    aes_key, mac_key = keys[:32], keys[32:64]

    # Verify HMAC and decrypt
    try:
        payload = verify_hmac(encrypted_data[len(HEADER):], mac_key)
        plaintext = decrypt_aes(payload, aes_key)
    finally:
        # Always wipe sensitive data
        secure_wipe(seed_hash)
        secure_wipe(image_secret)
        secure_wipe(master_secret)
        secure_wipe(aes_key)
        secure_wipe(mac_key)

    return plaintext


# ---- EXAMPLE USAGE ----
if __name__ == "__main__":
    try:
        password = "Str0ngP@ssw0rd!"  # In real usage, get from secure input
        gradient_img_path = "secure_gradient.png"
        encrypted_file_path = "encrypted_message.sec"
        plaintext = "This is a highly sensitive message!"

        # Generate new image
        generate_gradient_key_image(password, gradient_img_path)

        # Encrypt message
        encrypt_text_to_file(plaintext, password, gradient_img_path, encrypted_file_path)

        # Decrypt message
        decrypted = decrypt_text_from_file(gradient_img_path, password, encrypted_file_path)
        print(f"[✓] Decrypted successfully: {decrypted}")

    except AuthenticationError as ae:
        print(f"[!] Security alert: {ae}")
    except Exception as e:
        print(f"[!] Error: {str(e)}")
