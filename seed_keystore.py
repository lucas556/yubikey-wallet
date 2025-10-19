#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yk_piv_toolkit.py  (ECDH-only + Interactive Menu)
YubiKey PIV 管理 + PIV Key Agreement(ECDH P-256) 工具库（带交互菜单）

功能：
- 修改 PIN/PUK、设置重试次数
- 修改/设置管理密钥（Management Key）
- 在 9A/9C/9D/9E 槽生成 RSA/ECC 密钥
- 生成自签证书、导入/导出证书、导出公钥
- 通过 PIV Key Agreement（ECDH P-256）派生 32B 共享秘密 S_hw
- 列出 Token/对象（用于排障）
- 一键从 9D 派生 S_hw：derive_s_hw_9d()
- 重置/清空 PIV：piv_reset()
- 一键初始化：init_piv_ecdh_9d(reset=True) → 重置后在 9D 生成 ECCP256 + 写证书
- （新）交互式菜单：从命令行选择操作

依赖安装（macOS/Homebrew 示例）：
  brew install yubico-piv-tool yubikey-manager opensc openssl
  python3 -m pip install cryptography
"""
import os
import re
import sys
import json
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from typing import List, Optional

# --- ECDH 所需 ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime


PIV_SLOT_ID_HEX = {"9a": "01", "9c": "02", "9d": "03", "9e": "04"}


@dataclass
class ExecResult:
    code: int
    out: str
    err: str


def _which(cmd: str) -> Optional[str]:
    from shutil import which
    return which(cmd)


def _run(cmd: List[str], env: Optional[dict] = None, check: bool = False) -> ExecResult:
    cp = subprocess.run(cmd, text=True, capture_output=True, env=env)
    if check and cp.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {' '.join(cmd)}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )
    return ExecResult(cp.returncode, cp.stdout, cp.stderr)


def detect_libykcs11() -> str:
    candidates = [
        "/opt/homebrew/lib/libykcs11.dylib",   # Apple Silicon (brew)
        "/usr/local/lib/libykcs11.dylib",      # Intel macOS (brew)
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("无法找到 libykcs11（请安装 opensc 并确认路径）。")


class YubiKeyPIV:
    def __init__(self, token_label: Optional[str] = None, slot_index: Optional[int] = None,
                 libykcs11: Optional[str] = None, openssl_path: Optional[str] = None,
                 yubico_piv_tool: str = "yubico-piv-tool"):
        self.token_label = token_label
        self.slot_index = slot_index
        self.lib = libykcs11 or detect_libykcs11()
        self.openssl = openssl_path or _which("openssl") or "openssl"

        if not _which("ykman"):
            raise RuntimeError("未找到 ykman，请先安装 YubiKey Manager CLI")
        if not _which("pkcs11-tool"):
            raise RuntimeError("未找到 pkcs11-tool（OpenSC），请先安装")
        self.yubico_piv_tool = shutil.which(yubico_piv_tool) or yubico_piv_tool
        if not _which(self.yubico_piv_tool):
            raise RuntimeError("未找到 yubico-piv-tool，请先安装（brew install yubico-piv-tool）")

    # ---------- 基础信息/枚举 ----------

    def ykman_info(self) -> str:
        r = _run(["ykman", "info"])
        return r.out.strip()

    def list_objects(self, login: bool = False, pin: Optional[str] = None) -> str:
        cmd = ["pkcs11-tool", "--module", self.lib]
        if self.token_label:
            cmd += ["--token-label", self.token_label]
        elif self.slot_index is not None:
            cmd += ["--slot-index", str(self.slot_index)]
        if login:
            if not pin:
                raise ValueError("list_objects(login=True) 需要提供 pin")
            cmd += ["--login", "--login-type", "user", "--pin", pin]
        cmd += ["-O"]
        r = _run(cmd)
        return (r.out or r.err).strip()

    # ---------- 访问控制：PIN/PUK/管理密钥 ----------

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        _run(["ykman", "piv", "access", "change-pin", "--pin", old_pin, "--new-pin", new_pin], check=True)

    def change_puk(self, old_puk: str, new_puk: str) -> None:
        _run(["ykman", "piv", "access", "change-puk", "--puk", old_puk, "--new-puk", new_puk], check=True)

    def set_pin_retries(self, pin_tries: int, puk_tries: int, mgmt_key_hex: Optional[str] = None) -> None:
        cmd = ["ykman", "piv", "access", "set-pin-retries", str(pin_tries), str(puk_tries)]
        if mgmt_key_hex:
            cmd += ["-m", mgmt_key_hex]
        _run(cmd, check=True)

    def change_management_key(self, new_key_hex: str, algorithm: Optional[str] = None,
                              protect_with_pin: bool = False, pin: Optional[str] = None) -> None:
        cmd = ["ykman", "piv", "access", "change-management-key", "-m", new_key_hex]
        if algorithm:
            cmd += ["--algorithm", algorithm]
        if protect_with_pin:
            cmd += ["--protect"]
            if pin:
                cmd += ["--pin", pin]
        _run(cmd, check=True)

    # ---------- ykman 基础参数（可选按序列号选设备） ----------

    def _parse_serial_from_token_label(self) -> Optional[str]:
        if not self.token_label:
            return None
        m = re.search(r"#(\d+)$", self.token_label.strip())
        return m.group(1) if m else None

    def _ykman_cmd(self) -> List[str]:
        cmd = ["ykman"]
        serial = self._parse_serial_from_token_label()
        if serial:
            cmd += ["--device", serial]
        return cmd

    # ---------- 密钥/证书 ----------

    def generate_key(self, slot: str, algorithm: str, touch_policy: Optional[str] = None,
                     out_pub_pem: Optional[str] = None, mgmt_key_hex: Optional[str] = None) -> None:
        slot = slot.lower()
        assert slot in PIV_SLOT_ID_HEX, "slot 必须是 9a/9c/9d/9e"
        cmd = self._ykman_cmd() + ["piv", "keys", "generate"]
        if mgmt_key_hex:
            cmd += ["-m", mgmt_key_hex]
        cmd += ["--algorithm", algorithm]
        if touch_policy:
            cmd += ["--touch-policy", touch_policy]
        cmd += [slot]
        if out_pub_pem:
            cmd += [out_pub_pem]
        _run(cmd, check=True)

    def generate_self_signed_cert(self, slot: str, subject_cn: str, pub_pem_path: str,
                                  mgmt_key_hex: Optional[str] = None, pin: Optional[str] = None) -> None:
        slot = slot.lower()
        assert slot in PIV_SLOT_ID_HEX
        cmd = self._ykman_cmd() + ["piv", "certificates", "generate", "-s", f"CN={subject_cn}"]
        if mgmt_key_hex:
            cmd += ["-m", mgmt_key_hex]
        if pin:
            cmd += ["--pin", pin]
        cmd += [slot, pub_pem_path]
        _run(cmd, check=True)

    def import_certificate(self, slot: str, cert_pem_path: str, mgmt_key_hex: Optional[str] = None) -> None:
        slot = slot.lower()
        assert slot in PIV_SLOT_ID_HEX
        cmd = self._ykman_cmd() + ["piv", "certificates", "import"]
        if mgmt_key_hex:
            cmd += ["-m", mgmt_key_hex]
        cmd += [slot, cert_pem_path]
        _run(cmd, check=True)

    def export_certificate(self, slot: str, out_path: str) -> None:
        slot = slot.lower()
        assert slot in PIV_SLOT_ID_HEX
        cmd = self._ykman_cmd() + ["piv", "certificates", "export", slot, out_path]
        _run(cmd, check=True)

    def export_pubkey_from_cert(self, slot: str, out_pub_pem: str) -> None:
        tmp_cert = out_pub_pem + ".cert.tmp.pem"
        try:
            self.export_certificate(slot, tmp_cert)
            r = _run([self.openssl, "x509", "-in", tmp_cert, "-pubkey", "-noout"])
            if r.code != 0 or not r.out.strip():
                raise RuntimeError(f"openssl 提取公钥失败: {r.err or r.out}")
            with open(out_pub_pem, "w") as f:
                f.write(r.out)
        finally:
            try: os.remove(tmp_cert)
            except Exception: pass

    # ---------- 重置/清空 PIV ----------

    def piv_reset(self, method: str = "ykman", force: bool = True) -> None:
        if method == "ykman":
            cmd = self._ykman_cmd()
            if force:
                cmd += ["--force"]
            cmd += ["piv", "reset"]
        elif method == "pivtool":
            cmd = [self.yubico_piv_tool, "-a", "reset"]
        else:
            raise ValueError("method 必须是 'ykman' 或 'pivtool'")
        r = _run(cmd)
        if r.code != 0:
            raise RuntimeError(f"PIV 重置失败：{r.err or r.out}")

    # ---------- 一键初始化（重置→9D 生成 ECCP256→写证书） ----------

    def init_piv_ecdh_9d(self,
                         reset: bool = True,
                         subject_cn: str = "Wallet 9D ECDH Key",
                         touch_policy: str = "always",
                         mgmt_key_hex: Optional[str] = None,
                         pin: Optional[str] = None,
                         verbose: bool = False) -> None:
        if reset:
            if verbose: print("[INFO] 重置 PIV ...")
            self.piv_reset(method="ykman", force=True)
            if verbose: print("[OK] 已重置。")

        with tempfile.TemporaryDirectory(prefix="yk_init_") as tmpd:
            pub_pem = os.path.join(tmpd, "pub_9d.pem")
            if verbose: print("[INFO] 生成 9D 槽 ECCP256 密钥 ...")
            self.generate_key(slot="9d", algorithm="ECCP256",
                              touch_policy=touch_policy,
                              out_pub_pem=pub_pem,
                              mgmt_key_hex=mgmt_key_hex)
            if verbose: print("[OK] 已生成密钥，公钥保存于临时文件。")

            if verbose: print("[INFO] 写入 9D 自签证书 ...")
            self.generate_self_signed_cert(slot="9d",
                                           subject_cn=subject_cn,
                                           pub_pem_path=pub_pem,
                                           mgmt_key_hex=mgmt_key_hex,
                                           pin=pin)
            if verbose: print("[OK] 自签证书已写入 9D。")

    # ---------- PIV Key Agreement：ECDH P-256（核心） ----------

    def ecdh_shared_secret_p256(self, slot: str, pin: Optional[str], verbose: bool = False) -> bytes:
        slot = slot.lower()
        assert slot in PIV_SLOT_ID_HEX, "slot 必须是 9a/9c/9d/9e（且为 ECCP256 才能 ECDH）"

        eph_priv = ec.generate_private_key(ec.SECP256R1())
        cert_pem = self._make_min_selfsigned_cert_pem(eph_priv)

        with tempfile.TemporaryDirectory(prefix="yk_ecdh_") as tmpd:
            peer_cert_path = os.path.join(tmpd, "peer_cert.pem")
            out_secret_path = os.path.join(tmpd, "secret.bin")
            with open(peer_cert_path, "wb") as f:
                f.write(cert_pem)

            cmd = [self.yubico_piv_tool]
            if self.token_label:
                cmd += ["--reader", self.token_label]  # 某些版本参数为 --reader
            cmd += ["-a", "verify-pin", "-a", "test-decipher",
                    "-s", slot,
                    "-i", peer_cert_path,
                    "-o", out_secret_path]
            if pin:
                cmd += ["-P", pin]

            if verbose:
                print("[DEBUG] exec:", " ".join(self._mask_pin(cmd)), file=sys.stderr)

            cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if verbose:
                if cp.stdout: print("[DEBUG] stdout:", cp.stdout.decode(errors="ignore"), file=sys.stderr)
                if cp.stderr: print("[DEBUG] stderr:", cp.stderr.decode(errors="ignore"), file=sys.stderr)

            if cp.returncode != 0:
                raise RuntimeError(
                    f"yubico-piv-tool 执行失败（return={cp.returncode}）：\n"
                    f"{cp.stderr.decode(errors='ignore') or cp.stdout.decode(errors='ignore')}"
                )

            if not os.path.exists(out_secret_path):
                raise RuntimeError("未找到 ECDH 输出文件（secret.bin）。请确认该槽位是 ECCP256 私钥。")

            shared = open(out_secret_path, "rb").read()

        if len(shared) != 32:
            raise RuntimeError(f"ECDH 返回长度 {len(shared)}，预期 P-256 为 32。")
        return shared

    # ---------- 一键从 9D 槽派生 S_hw ----------

    def derive_s_hw_9d(self, pin: Optional[str], out_path: Optional[str] = None,
                       verbose: bool = False) -> bytes:
        s_hw = self.ecdh_shared_secret_p256(slot="9d", pin=pin, verbose=verbose)
        if out_path:
            with open(out_path, "wb") as f:
                f.write(s_hw)
        return s_hw

    # ---------- 辅助 ----------

    @staticmethod
    def _make_min_selfsigned_cert_pem(priv: ec.EllipticCurvePrivateKey) -> bytes:
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Ephemeral ECDH Peer")])
        now = datetime.datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
        )
        cert = builder.sign(private_key=priv, algorithm=hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def _mask_pin(argv: List[str]) -> List[str]:
        masked, skip = [], False
        for tok in argv:
            if skip:
                masked.append("******"); skip = False
            elif tok in ("-P", "--pin"):
                masked.append(tok); skip = True
            else:
                masked.append(tok)
        return masked


# -------------------- 交互式菜单 --------------------
def _prompt(msg: str) -> str:
    try:
        return input(msg)
    except EOFError:
        return ""

def _confirm(msg: str) -> bool:
    ans = _prompt(msg + " [y/N]: ").strip().lower()
    return ans in ("y", "yes")

if __name__ == "__main__":
    import getpass

    # 设备选择（可留空）
    token_label = _prompt("可选：输入 token label（例如 YubiKey PIV #28616027），直接回车跳过：").strip() or None
    yk = YubiKeyPIV(token_label=token_label)

    while True:
        print("\n=== YubiKey PIV 工具菜单 ===")
        print("1) 查看 ykman info")
        print("2) 列对象（未登录）")
        print("3) 列对象（登录后显示 PRIVATE KEY）")
        print("4) 一键初始化 9D 为 ECDH(P-256)（可选重置）")
        print("5) 从 9D 派生 32B S_hw（ECDH）")
        print("6) 修改 PIN")
        print("7) 修改 PUK")
        print("8) 设置 PIN/PUK 重试次数")
        print("9) 修改管理密钥（Management Key）")
        print("10) 导出 9D 证书公钥到文件")
        print("11) 导出槽位证书到文件")
        print("12) 导入证书到槽位")
        print("13) 重置 PIV（危险！清空）")
        print("0) 退出")
        choice = _prompt("请选择：").strip()

        try:
            if choice == "1":
                print("\n== ykman info ==")
                print(yk.ykman_info())

            elif choice == "2":
                print("\n== 列对象(未登录) ==")
                print(yk.list_objects(login=False))

            elif choice == "3":
                pin = getpass.getpass("输入 PIN（默认 123456，可直接回车使用默认）：") or "123456"
                print("\n== 列对象(已登录) ==")
                print(yk.list_objects(login=True, pin=pin))

            elif choice == "4":
                do_reset = _confirm("是否先重置 PIV？（会清空所有内容！）")
                subj = _prompt("证书 CN（默认: Wallet 9D ECDH Key）：").strip() or "Wallet 9D ECDH Key"
                touch = _prompt("触摸策略（always/cached/never，默认 always）：").strip() or "always"
                mgmt = _prompt("管理密钥 hex（留空则交互处理/使用默认）：").strip() or None
                pin = getpass.getpass("（可选）PIN（默认 123456 可回车跳过）：") or None
                yk.init_piv_ecdh_9d(reset=do_reset, subject_cn=subj,
                                    touch_policy=touch, mgmt_key_hex=mgmt,
                                    pin=pin, verbose=True)
                print("[OK] 初始化完成。")

            elif choice == "5":
                pin = getpass.getpass("输入 PIN（默认 123456，可直接回车使用默认）：") or "123456"
                outp = _prompt("可选：输出到文件路径（回车跳过）：").strip() or None
                s = yk.derive_s_hw_9d(pin=pin, out_path=outp, verbose=True)
                print(f"[OK] S_hw length = {len(s)}")
                print(f"[OK] S_hw (first 16 bytes) = {s[:16].hex()}")

            elif choice == "6":
                oldp = getpass.getpass("旧 PIN：")
                newp = getpass.getpass("新 PIN：")
                yk.change_pin(oldp, newp)
                print("[OK] PIN 已修改。")

            elif choice == "7":
                oldk = getpass.getpass("旧 PUK：")
                newk = getpass.getpass("新 PUK：")
                yk.change_puk(oldk, newk)
                print("[OK] PUK 已修改。")

            elif choice == "8":
                tries_pin = int(_prompt("PIN 重试次数（例如 3）：").strip())
                tries_puk = int(_prompt("PUK 重试次数（例如 3）：").strip())
                mgmt = _prompt("管理密钥 hex（留空则交互处理/使用默认）：").strip() or None
                yk.set_pin_retries(tries_pin, tries_puk, mgmt_key_hex=mgmt)
                print("[OK] 重试次数已设置。")

            elif choice == "9":
                new_key = _prompt("新管理密钥（hex，例如 24/32 字节）：").strip()
                algo = _prompt("算法（例如 AES192；留空默认）：").strip() or None
                protect = _confirm("是否与 PIN 绑定 protect？")
                pin = getpass.getpass("（若 protect）请输入 PIN（可回车跳过）：") or None
                yk.change_management_key(new_key, algorithm=algo, protect_with_pin=protect, pin=pin)
                print("[OK] 管理密钥已修改。")

            elif choice == "10":
                outp = _prompt("输出公钥 PEM 路径（例如 pub_9d.pem）：").strip()
                yk.export_pubkey_from_cert("9d", outp)
                print(f"[OK] 已导出到 {outp}")

            elif choice == "11":
                slot = _prompt("槽位（9a/9c/9d/9e）：").strip().lower()
                outp = _prompt("输出证书 PEM 路径：").strip()
                yk.export_certificate(slot, outp)
                print(f"[OK] 已导出到 {outp}")

            elif choice == "12":
                slot = _prompt("槽位（9a/9c/9d/9e）：").strip().lower()
                cert = _prompt("待导入证书 PEM 路径：").strip()
                mgmt = _prompt("管理密钥 hex（留空则交互处理/使用默认）：").strip() or None
                yk.import_certificate(slot, cert, mgmt_key_hex=mgmt)
                print("[OK] 证书已导入。")

            elif choice == "13":
                if _confirm("确认重置 PIV？此操作会清空所有内容且不可恢复！"):
                    yk.piv_reset(method="ykman", force=True)
                    print("[OK] 已重置 PIV。")
                else:
                    print("[INFO] 已取消。")

            elif choice == "0":
                print("Bye.")
                break

            else:
                print("无效选择，请重试。")

        except Exception as e:
            print("[ERR]", e)
