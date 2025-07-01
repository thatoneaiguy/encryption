# GradientKey Encryption 🔐🎨

> A novel encryption system leveraging visually encoded color gradients as cryptographic keys.  
> Combine art and cryptography — hide your AES keys in gradients, and secure your secrets with style.

---

## Table of Contents

- [Introduction](#introduction)  
- [Concept & Design](#concept--design)  
- [How It Works](#how-it-works)  
- [Features](#features)  
- [Security Considerations](#security-considerations)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Configuration](#configuration)  
- [Development & Testing](#development--testing)  
- [Limitations & Future Work](#limitations--future-work)  
- [License](#license)  
- [Acknowledgments](#acknowledgments)

---

## Introduction

Traditional encryption relies on secret keys stored or transmitted as strings. **GradientKey Encryption** innovates by embedding cryptographic keys into images — specifically, gradients made up of multiple colors — turning a key into a visual artifact. This blends cryptography with steganography and creative data encoding.

Use it to:

- Hide keys in images that look like normal colorful gradients  
- Generate complex keys tied to user passwords and image content  
- Encrypt and decrypt text securely with AES-256 underpinned by visual keys  

---

## Concept & Design

- **Gradient Image as Key Container**:  
  A horizontally blended color gradient image contains multiple hidden salts and a 32-bit binary key encoded in pixel color channels.

- **Salts & Obfuscation**:  
  Multiple salts are embedded in separate horizontal bars in the image. The exact salt used is derived from a hash of the image size, colors count, and password, thwarting simple extraction.

- **Key Derivation**:  
  Using PBKDF2 with HMAC-SHA256 and the selected salt, a key hash seeds the gradient’s colors and the key binary embedding positions — binding the key tightly to both image and password.

- **AES Encryption**:  
  The extracted key binary is converted into an AES-256 key (SHA256 of numeric key). AES-CBC mode with random IV and PKCS7 padding encrypts/decrypts messages.

---

## How It Works

### Key Generation  
1. Password + random salts → PBKDF2 hash → Seed hash  
2. Generate 10 gradient colors based on seed hash  
3. Create gradient image (800x100 px)  
4. Embed salts as bits in top horizontal bars  
5. Embed 32-bit binary key pseudo-randomly across pixels  
6. Save gradient image (`gradient_output.png`)  

### Encryption  
1. Load gradient image + password  
2. Extract salts, select correct salt by hashed parameters  
3. Derive seed hash from password + selected salt  
4. Extract binary key from pixels  
5. Derive AES key from binary key  
6. Generate random IV, encrypt plaintext using AES-CBC with PKCS7  
7. Save encrypted file (`encrypted_message.bin`) as [IV + ciphertext]  

### Decryption  
- Reverse the encryption process: extract AES key from gradient image + password, then decrypt the encrypted file.

---

## Features

- 🔑 **Visually encoded AES key** in a colorful gradient  
- 🧂 Multiple embedded salts to prevent reverse-engineering  
- 🔒 AES-256 CBC encryption with PKCS7 padding  
- 🖼️ Image-based key sharing — passwords alone won’t decrypt  
- 🔍 Pseudo-random embedding for subtle, hard-to-detect key bits  
- ⚙️ Easy-to-run all-in-one Python script (generate, encrypt, decrypt)  

---

## Security Considerations

> ⚠️ This project is a **proof-of-concept** and should not be used for critical production data without thorough security review.

- The strength depends heavily on the password and securely keeping the gradient image.  
- Salts and random embedding make key extraction hard but not impossible with advanced analysis.  
- The 32-bit embedded key binary might be brute forced with enough computing power — consider expanding or varying size.  
- AES key derivation uses PBKDF2 with 100,000 iterations — secure but adjustable for your needs.

---

## Installation

Ensure you have Python 3.8+ installed.

Install dependencies:

```bash
pip install pillow pycryptodome
