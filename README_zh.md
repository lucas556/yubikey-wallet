# 🔐 基于 YubiKey FIDO2 的以太坊私钥加密器

使用 **YubiKey FIDO2 PRF (HMAC-Secret)** 扩展与 **AES-256-GCM + HKDF-SHA256** 构建的硬件加密钱包工具。
你的私钥由 YubiKey 生成和保护，**不依赖密码，不可导出**。

---

## 🚀 功能简介

| 功能 | 描述 |
|------|------|
| 🔑 使用 YubiKey FIDO2 PRF 生成加密密钥（KEK） | 无需用户密码，安全来源于硬件 |
| 🪙 自动生成以太坊私钥与地址 | 支持标准 EVM 地址（Keccak-256 + EIP-55） |
| 🔐 使用 AES-256-GCM 加密私钥 | 确保私钥保密性与完整性 |
| 📁 生成标准化 JSON keystore 文件 | 可保存多个地址的加密私钥 |
| 🔓 通过 YubiKey 解密私钥 | 需 PIN 与触摸验证 |
| 🧩 可扩展至 BTC / TRON 等链 | 设计通用，可按链种扩展 |

---

## ⚙️ 安装依赖

```bash
pip install fido2 cryptography pycryptodome
```

> 需要支持 FIDO2 + PRF 的 YubiKey（如 YubiKey 5C/5N/5 NFC）。

---

## 🧩 使用方法

运行主程序：

```bash
python3 seed_keystore.py
```

### 菜单选项：

```
==============================
 1) 生成并写入新以太坊地址（追加到 keystore）
 2) 解密某个地址的私钥（从 keystore）
 3) 创建新的 FIDO2 凭证并打印 rp_id / credential_id
 0) 退出
==============================
```

---

### ① 创建新的 FIDO2 凭证

```
=== 创建新的 FIDO2 凭证并打印 rp_id / credential_id ===
输入 rp_id [wallet.local]:
请触摸 YubiKey…
✅ 新凭证创建成功：
   rp_id         : wallet.local
   credential_id : 006d55e152a8b1e4...
```

---

### ② 生成并加密新地址

```
ok: new address: 0x8784c4c3e34168Ab3E49dEb74937Cf8F3847dA2d
请触摸 YubiKey…
✅ 已写入 privkey_keystore.json
```

---

### ③ 解密某个地址的私钥

```
addresses:
  1) 0x8784c4c3e34168Ab3E49dEb74937Cf8F3847dA2d  id=c38c96c8…
pick index [1-1]: 1
请输入 YubiKey PIN:
请触摸 YubiKey…
✅ 解密成功
privkey(hex): f3b9d5b4...
```

---

## 📦 keystore 文件结构

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

## 🔐 加密流程

```
1. 随机生成 32 字节 secp256k1 私钥
2. YubiKey 执行 PRF(salt_prf) → 32B
3. HKDF-SHA256(PRF_output, info=b"privkey-v1") → KEK
4. AES-256-GCM(KEK).encrypt(privkey)
5. 保存至 JSON keystore
```

解密时重复步骤 2–4 恢复原始私钥。

---

## ⚠️ 注意事项

- 丢失 YubiKey 或 Credential ID 将导致私钥无法解密  
- 每个地址使用独立 salt_prf，确保唯一密钥  
- `rp_id` 必须与注册时一致  
- 强烈建议仅在离线环境下使用  
- YubiKey 必须启用 FIDO2 应用并支持 HMAC-Secret 扩展  

---

## 🧱 技术栈

| 模块 | 功能 |
|------|------|
| `fido2` | 调用 YubiKey FIDO2 PRF 接口 |
| `cryptography` | ECC 密钥生成与 AES-GCM 加密 |
| `pycryptodome` | Keccak-256 哈希计算 |
| `HKDF-SHA256` | 从 PRF 输出派生 256-bit KEK |

---

## 📄 许可证

**MIT License © 2025 Lucas**
