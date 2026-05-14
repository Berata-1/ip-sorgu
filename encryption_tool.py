import os
import sys
import io
import argparse
import getpass
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[HATA] 'cryptography' paketi gerekli: pip install cryptography")
    sys.exit(1)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Dosya formatı: MAGIC(4) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG
MAGIC = b"ENCF"
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERATIONS = 600_000


def anahtar_turet(sifre: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(sifre.encode("utf-8"))


def dosya_sifrele(kaynak: str, hedef: str, sifre: str) -> None:
    kaynak_yol = Path(kaynak)
    if not kaynak_yol.exists():
        print(f"[HATA] Dosya bulunamadı: {kaynak}")
        sys.exit(1)

    if not hedef:
        hedef = kaynak + ".enc"

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    anahtar = anahtar_turet(sifre, salt)

    veri = kaynak_yol.read_bytes()
    aesgcm = AESGCM(anahtar)
    sifrelenmis = aesgcm.encrypt(nonce, veri, None)

    with open(hedef, "wb") as f:
        f.write(MAGIC + salt + nonce + sifrelenmis)

    boyut_kb = kaynak_yol.stat().st_size / 1024
    print(f"[OK] Şifrelendi   : {kaynak}  ({boyut_kb:.1f} KB)")
    print(f"     Çıktı dosyası: {hedef}")
    print(f"     Algoritma    : AES-256-GCM | PBKDF2-SHA256 ({PBKDF2_ITERATIONS:,} iter)")


def dosya_coz(kaynak: str, hedef: str, sifre: str) -> None:
    kaynak_yol = Path(kaynak)
    if not kaynak_yol.exists():
        print(f"[HATA] Dosya bulunamadı: {kaynak}")
        sys.exit(1)

    ham = kaynak_yol.read_bytes()

    if not ham.startswith(MAGIC):
        print("[HATA] Bu dosya encryption_tool ile şifrelenmemiş veya bozuk.")
        sys.exit(1)

    offset = len(MAGIC)
    salt = ham[offset: offset + SALT_LEN]
    offset += SALT_LEN
    nonce = ham[offset: offset + NONCE_LEN]
    offset += NONCE_LEN
    sifrelenmis = ham[offset:]

    anahtar = anahtar_turet(sifre, salt)
    aesgcm = AESGCM(anahtar)

    try:
        acik_veri = aesgcm.decrypt(nonce, sifrelenmis, None)
    except Exception:
        print("[HATA] Şifre yanlış veya dosya bozuk — çözme başarısız.")
        sys.exit(1)

    if not hedef:
        hedef = kaynak.removesuffix(".enc") if kaynak.endswith(".enc") else kaynak + ".dec"

    with open(hedef, "wb") as f:
        f.write(acik_veri)

    boyut_kb = len(acik_veri) / 1024
    print(f"[OK] Çözüldü      : {kaynak}  ({boyut_kb:.1f} KB)")
    print(f"     Çıktı dosyası: {hedef}")


def klasor_sifrele(klasor: str, sifre: str) -> None:
    klasor_yol = Path(klasor)
    if not klasor_yol.is_dir():
        print(f"[HATA] Klasör bulunamadı: {klasor}")
        sys.exit(1)

    dosyalar = [f for f in klasor_yol.rglob("*") if f.is_file() and not f.suffix == ".enc"]
    if not dosyalar:
        print("[BILGI] Şifrelenecek dosya bulunamadı.")
        return

    print(f"[INFO] {len(dosyalar)} dosya şifrelenecek...\n")
    for dosya in dosyalar:
        dosya_sifrele(str(dosya), str(dosya) + ".enc", sifre)
    print(f"\n[OK] Toplam {len(dosyalar)} dosya şifrelendi.")


def klasor_coz(klasor: str, sifre: str) -> None:
    klasor_yol = Path(klasor)
    if not klasor_yol.is_dir():
        print(f"[HATA] Klasör bulunamadı: {klasor}")
        sys.exit(1)

    dosyalar = [f for f in klasor_yol.rglob("*.enc") if f.is_file()]
    if not dosyalar:
        print("[BILGI] Çözülecek .enc dosyası bulunamadı.")
        return

    print(f"[INFO] {len(dosyalar)} dosya çözülecek...\n")
    basarili = 0
    for dosya in dosyalar:
        try:
            dosya_coz(str(dosya), None, sifre)
            basarili += 1
        except SystemExit:
            print(f"     [ATLANDI] {dosya.name}")
    print(f"\n[OK] {basarili}/{len(dosyalar)} dosya çözüldü.")


def sifre_al(dogrula: bool = False) -> str:
    sifre = getpass.getpass("Şifre: ")
    if not sifre:
        print("[HATA] Şifre boş olamaz.")
        sys.exit(1)
    if dogrula:
        tekrar = getpass.getpass("Şifre (tekrar): ")
        if sifre != tekrar:
            print("[HATA] Şifreler eşleşmiyor.")
            sys.exit(1)
    return sifre


def main():
    parser = argparse.ArgumentParser(
        prog="encryption_tool",
        description="AES-256-GCM ile dosya ve klasör şifreleme/çözme aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python encryption_tool.py encrypt dosya.pdf
  python encryption_tool.py encrypt dosya.pdf -o sifreli.enc
  python encryption_tool.py decrypt sifreli.enc
  python encryption_tool.py decrypt sifreli.enc -o cikti.pdf
  python encryption_tool.py encrypt-dir ./belgeler
  python encryption_tool.py decrypt-dir ./belgeler
        """,
    )

    alt = parser.add_subparsers(dest="komut", required=True)

    # encrypt
    enc = alt.add_parser("encrypt", help="Tek dosya şifrele")
    enc.add_argument("dosya", help="Şifrelenecek dosya")
    enc.add_argument("-o", "--output", help="Çıktı dosyası (varsayılan: dosya.enc)", default=None)

    # decrypt
    dec = alt.add_parser("decrypt", help="Tek dosya çöz")
    dec.add_argument("dosya", help="Çözülecek .enc dosyası")
    dec.add_argument("-o", "--output", help="Çıktı dosyası", default=None)

    # encrypt-dir
    edir = alt.add_parser("encrypt-dir", help="Klasördeki tüm dosyaları şifrele")
    edir.add_argument("klasor", help="Şifrelenecek klasör")

    # decrypt-dir
    ddir = alt.add_parser("decrypt-dir", help="Klasördeki tüm .enc dosyalarını çöz")
    ddir.add_argument("klasor", help="Çözülecek klasör")

    args = parser.parse_args()

    if args.komut == "encrypt":
        sifre = sifre_al(dogrula=True)
        dosya_sifrele(args.dosya, args.output, sifre)

    elif args.komut == "decrypt":
        sifre = sifre_al(dogrula=False)
        dosya_coz(args.dosya, args.output, sifre)

    elif args.komut == "encrypt-dir":
        sifre = sifre_al(dogrula=True)
        klasor_sifrele(args.klasor, sifre)

    elif args.komut == "decrypt-dir":
        sifre = sifre_al(dogrula=False)
        klasor_coz(args.klasor, sifre)


if __name__ == "__main__":
    main()
