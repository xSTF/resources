# Cryptography CTF Guide for Beginners

## What is Cryptography in CTFs?

Cryptography ("crypto") in CTF competitions involves solving challenges related to encryption, encoding, and secure communications. Unlike academic cryptography which focuses on creating secure systems, CTF crypto challenges typically involve:

- Breaking weak or improperly implemented encryption
- Decoding messages using various algorithms
- Exploiting mathematical vulnerabilities
- Analyzing cryptographic protocols for flaws

Crypto challenges test your understanding of mathematical concepts, ability to recognize patterns, and knowledge of common encryption methods and their weaknesses.

## Key Terminology

- **Plaintext**: The original, readable message
- **Ciphertext**: The encrypted, scrambled message
- **Key**: Information used to control the encryption/decryption process
- **Encryption**: Process of converting plaintext to ciphertext
- **Decryption**: Process of converting ciphertext back to plaintext
- **Encoding**: Converting data into another format (not for security)
- **Cipher**: An algorithm for performing encryption or decryption
- **Hash**: One-way function that maps data of arbitrary size to fixed-size values
- **Salt**: Random data added to a hash function to prevent rainbow table attacks
- **Initialization Vector (IV)**: Random value used with encryption algorithms
- **Block cipher**: Encrypts fixed-size blocks of data
- **Stream cipher**: Encrypts continuous streams of data
- **Public/Private keys**: Key pairs used in asymmetric encryption

## Common Crypto CTF Challenge Types

### 1. **Classical Ciphers**
- Basic substitution and transposition ciphers (Caesar, Vigenère, etc.)
- Often require pattern recognition and frequency analysis

### 2. **Modern Symmetric Cryptography**
- Challenges involving AES, DES, etc.
- Usually focus on implementation flaws or mode vulnerabilities

### 3. **Asymmetric Cryptography**
- RSA, Diffie-Hellman, ECC challenges
- Often involve mathematical attacks or parameter weaknesses

### 4. **Hash Functions**
- MD5, SHA family, etc.
- Commonly involve collision attacks or brute forcing

### 5. **Encoding Schemes**
- Base64, Hex, ASCII, etc.
- Often used as building blocks in more complex challenges

### 6. **Custom Cryptosystems**
- Unique algorithms designed specifically for the challenge
- Require analysis and reverse engineering

### 7. **Side-Channel Attacks**
- Exploiting information gained from implementation (timing, etc.)
- Often combine cryptography with other categories like PWN

## Essential Tools for Crypto Challenges

### General Tools

**1. CyberChef**
- Web-based tool for encoding, encryption, and analysis
- **When to use**: Quick transformations and multi-step operations

**2. Python + Libraries**
- Cryptography, PyCrypto, gmpy2, SymPy
- **When to use**: Scripting custom solutions or implementing attacks

**3. SageMath**
- Mathematical software system
- **When to use**: Advanced mathematical operations and attacks

**4. RsaCtfTool**
- Automated RSA vulnerability checker
- **When to use**: When facing RSA challenges to quickly test for common vulnerabilities

**5. HashCat/John the Ripper**
- Password cracking tools
- **When to use**: When you need to brute force hashes

### Online Resources

**1. dcode.fr**
- Collection of decoders for various ciphers
- **When to use**: Quick analysis of classical ciphers

**2. quipqiup.com**
- Automated cryptogram solver
- **When to use**: For solving simple substitution ciphers

**3. factordb.com**
- Database of factorized numbers
- **When to use**: RSA challenges where you need to factor N

## Common Cryptographic Algorithms and Vulnerabilities

### Classical Ciphers

**1. Caesar Cipher**
- Simple substitution cipher with fixed shift
- **Vulnerability**: Only 25 possible shifts to try

**2. Vigenère Cipher**
- Polyalphabetic substitution with a repeating key
- **Vulnerability**: Frequency analysis and Kasiski examination

**3. Substitution Cipher**
- Each letter replaced by another letter
- **Vulnerability**: Frequency analysis

### Modern Symmetric Encryption

**1. AES (Advanced Encryption Standard)**
- Block cipher with 128/192/256 bit keys
- **Vulnerabilities**: Implementation flaws, mode of operation issues (ECB, CBC padding oracle)

**2. DES/3DES**
- Older block ciphers
- **Vulnerabilities**: Small key space (DES), meet-in-the-middle attacks (3DES)

**3. XOR Encryption**
- Simple bitwise operation
- **Vulnerabilities**: Reused keys, known plaintext attacks

### Asymmetric Encryption

**1. RSA**
- Based on factoring large primes
- **Vulnerabilities**:
  - Small primes
  - Common modulus attack
  - Low public exponent (small e)
  - Wiener's attack (small private exponent)
  - Coppersmith's attack
  - Hastad's broadcast attack

**2. Diffie-Hellman**
- Key exchange protocol
- **Vulnerabilities**: Small primes, weak parameters

### Hash Functions

**1. MD5/SHA1**
- Older hash functions
- **Vulnerabilities**: Collision attacks

**2. SHA-256/SHA-3**
- Modern hash functions
- **Vulnerabilities**: Length extension attacks (SHA-256)

## Step-by-Step Approach to Crypto Challenges

1. **Identify the Cryptosystem**
   - Analyze the given information (ciphertext format, key information)
   - Look for telltale patterns or characteristics

2. **Research Known Vulnerabilities**
   - Once identified, research common attacks against the system
   - Check for implementation mistakes or weak parameters

3. **Select and Apply Tools**
   - Choose appropriate tools based on the cryptosystem
   - Script custom solutions if needed

4. **Analyze Results**
   - Check if output resembles plaintext or contains the flag
   - Look for patterns that might require further decryption

5. **Iterate if Necessary**
   - If initial approach fails, try alternative attacks
   - Consider combinations of techniques

## Practical Tips for Beginners

- **Learn to recognize encodings** (Base64, Hex, etc.) by their patterns
- **Check for common RSA vulnerabilities first** when facing RSA challenges
- **XOR is everywhere** - learn to recognize and exploit XOR patterns
- **Pay attention to padding** in block ciphers
- **Consider frequency analysis** for substitution ciphers
- **Look for patterns in ciphertext** that might reveal encryption method
- **Always try the simplest approach first** (e.g., standard libraries, known attacks)
- **Keep a cheat sheet** of common cryptographic formulas and attacks
- **Remember that flags are usually readable** - if your result looks random, it's probably wrong

## Common Encodings to Recognize

- **Base64**: Contains A-Z, a-z, 0-9, +, /, and possibly = padding at the end
- **Hexadecimal**: Uses characters 0-9 and A-F
- **Binary**: Contains only 0s and 1s
- **ASCII values**: Numbers typically in the range 32-126
- **Octal**: Contains digits 0-7

## Practice Resources

- **Beginner-friendly platforms**:
  - CryptoHack (interactive cryptography challenges)
  - PicoCTF (start with the easiest crypto challenges)
  - Cryptopals Crypto Challenges

Remember that cryptography challenges often require mathematical thinking and pattern recognition. Start with simpler challenges to build your skills and gradually move to more complex ones as you improve your understanding of cryptographic concepts.
