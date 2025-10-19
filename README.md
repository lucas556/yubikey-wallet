# 🔐 YubiKey FIDO2 Ethereum Key Encryptor

A hardware-backed Ethereum key vault using **YubiKey FIDO2 PRF (HMAC-Secret)** and **AES-256-GCM + HKDF-SHA256**.
Your encryption key is derived securely from the YubiKey — **no passwords, no exportable secrets.**

---

## 🚀 Features

| Feature | Description |
|----------|--------------|
| 🔑 Hardware-based key derivation using YubiKey FIDO2 PRF | No password required, hardware-secure |
| 🪙 Auto-generates Ethereum private keys and addresses | EVM-standard (Keccak-256 + EIP-55 checksum) |
| 🔐 AES-256-GCM encryption of private keys | Ensures confidentiality & integrity |
| 📁 JSON keystore supporting multiple addresses | Each entry independently encrypted |
| 🔓 Decrypt via YubiKey with PIN & touch | FIDO2 authentication enforced |
| 🧩 Extensible to BTC / TRON in the future | Chain-agnostic design |

---

## ⚙️ Installation

```bash
pip install fido2 cryptography pycryptodome
```

Requires a **YubiKey 5 / FIDO2-compatible device** with HMAC-Secret (PRF) extension enabled.

---

## 🧩 Usage

Run the main program:

```bash
python3 seed_keystore.py
```

### Menu options

```
==============================
 1) generate and append new ethereum address
 2) decrypt one address
 3) create new fido2 credential and print rp_id / credential_id
 0) exit
==============================
```

---

### ① Create new FIDO2 credential

```
=== create a new fido2 credential and print rp_id / credential_id ===
enter rp_id [wallet.local]:
please touch your YubiKey...
ok: created new credential
  rp_id         : wallet.local
  credential_id : 006d55e152a8b1e4...
```

---

### ② Generate and encrypt new address

```
ok: new address: 0x8784c4c3e34168Ab3E49dEb74937Cf8F3847dA2d
please touch your YubiKey...
written: privkey_keystore.json
```

---

### ③ Decrypt stored address

```
addresses:
  1) 0x8784c4c3e34168Ab3E49dEb74937Cf8F3847dA2d  id=c38c96c8…
pick index [1-1]: 1
please touch your YubiKey...
ok: decrypted
privkey(hex): f3b9d5b4...
```

> ⚠️ Only view decrypted private keys in an **offline and secure environment.**

---

## 📦 Keystore structure

```json
{
  "rp_id": "wallet.local",
  "kdf": "fido2-prf+hkdf-sha256",
  "kdfparams": {
    "rp_id": "wallet.local",
    "credential_id": "006d55e152a8...",
    "info": "privkey-v1"
  },
  "entries": [
    {
      "id": "c38c96c8-77db-45a1-87d5-16b1e583b1e8",
      "address": "0x8784c4c3e34168Ab3E49dEb74937Cf8F3847dA2d",
      "salt_prf": "6e4f...d2b",
      "crypto": {
        "cipher": "aes-256-gcm",
        "iv": "74b37f...",
        "ciphertext": "de31c9..."
      }
    }
  ]
}
```

---

## 🔐 Encryption Process

```
1. generate 32-byte random secp256k1 private key
2. yubikey computes PRF(salt_prf) → 32 bytes
3. HKDF-SHA256(PRF_output, info=b"privkey-v1") → KEK
4. AES-256-GCM(KEK).encrypt(privkey)
5. save to JSON keystore
```

---

## ⚠️ Notes

- Losing the YubiKey or credential_id makes decryption impossible
- Each entry has unique salt_prf
- `rp_id` must match during decrypt
- Run only in secure/offline environments
- YubiKey must have FIDO2 + HMAC-Secret enabled

---

## 🧱 Tech Stack

| Module | Purpose |
|---------|----------|
| `fido2` | YubiKey FIDO2 PRF operations |
| `cryptography` | ECC key generation & AES-GCM encryption |
| `pycryptodome` | Keccak-256 hashing for Ethereum |
| `HKDF-SHA256` | Derive 256-bit KEK from PRF output |

---

## 📄 License

**MIT License © 2025 Lucas**
