# 🔐 RSA-Based Certificate Authority and Secure Messaging System

This project simulates a simplified Certificate Authority (CA) system using a custom RSA cryptosystem. It supports secure client registration, certificate issuance, digital signature verification, and encrypted communication between authenticated clients.

## 📌 Features

- 🔑 **RSA Key Pair Generation** (1024-bit keys)
- 🧾 **Certificate Authority**
  - Registers clients by their public key
  - Issues signed digital certificates with timestamp and validity
- ✅ **Client-Side Certificate Verification**
- 📬 **Secure Message Exchange**
  - Encrypts messages using recipient’s public key
  - Sends signed acknowledgments
- 🔐 **Custom RSA Implementation** with:
  - Key generation
  - Encryption & Decryption
  - Digital signing & verification using SHA-256

---


