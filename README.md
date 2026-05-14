# Güvenlik Araçları Koleksiyonu

> **Uyarı:** Bu araçlar yalnızca kendi sistemlerinizde veya **yazılı izin alınmış** hedeflerde kullanılabilir. Yetkisiz kullanım yasa dışıdır.

---

## PenTest Suite

Kapsamlı güvenlik test aracı — 9 modül tek programda.

### Kurulum

```bash
pip install -r requirements.txt
```

### İnteraktif Menü

```bash
python pentest_suite.py
```

### CLI Kullanımı

```bash
# Hash kırıcı
python pentest_suite.py hash 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt

# HTTP login brute force
python pentest_suite.py http http://site.com/login -u admin -w passwords.txt --fail-text "Hatalı şifre"

# SSH brute force
python pentest_suite.py ssh 192.168.1.1 -u root -w passwords.txt -p 22 -t 5

# FTP brute force
python pentest_suite.py ftp 192.168.1.1 -u admin -w passwords.txt

# ZIP şifre kırma
python pentest_suite.py zip dosya.zip -w passwords.txt

# RAR şifre kırma
python pentest_suite.py rar dosya.rar -w passwords.txt

# Port tarama
python pentest_suite.py portscan 192.168.1.1 --range 1-65535 -t 200

# Directory fuzzer
python pentest_suite.py dirbust http://site.com -w dirlist.txt -e .php,.html -t 30

# Subdomain tarayıcı
python pentest_suite.py subdomain example.com -w subdomains.txt -t 50

# JWT secret kırıcı
python pentest_suite.py jwt eyJhbGci... -w secrets.txt

# Sonuçları dosyaya kaydet
python pentest_suite.py -o sonuclar.txt portscan 192.168.1.1
```

### Modüller

| # | Modül | Açıklama |
|---|-------|----------|
| 1 | **Hash Cracker** | MD5, SHA1, SHA256, SHA512, bcrypt |
| 2 | **HTTP Brute Force** | Form login + Basic Auth, thread destekli |
| 3 | **SSH Brute Force** | Paramiko tabanlı SSH kimlik testi |
| 4 | **FTP Brute Force** | FTP servis kimlik testi |
| 5 | **ZIP Cracker** | Şifreli ZIP arşiv kırıcı |
| 6 | **RAR Cracker** | Şifreli RAR arşiv kırıcı |
| 7 | **Port Scanner** | TCP port tarayıcı, 18 servis tanımlı |
| 8 | **Directory Fuzzer** | Web dizin/dosya keşfi, uzantı desteği |
| 9 | **Subdomain Scanner** | DNS brute force ile subdomain keşfi |
| 10 | **JWT Tester** | HS256/384/512 secret key kırıcı |

---

# IP Sorgulama Aracı

Bir IP adresi veya domain hakkında konum, port ve WHOIS bilgilerini terminalde sorgular.

## Kurulum

```bash
pip install python-whois
```

## Kullanım

```bash
python -X utf8 ip_sorgu.py <IP veya domain>          # Tam sorgu (Konum + Port + WHOIS)
python -X utf8 ip_sorgu.py <IP veya domain> --ip     # Sadece konum bilgisi
python -X utf8 ip_sorgu.py <IP veya domain> --port   # Sadece port tarama
python -X utf8 ip_sorgu.py <IP veya domain> --whois  # Sadece WHOIS bilgisi
```

## Örnekler

```bash
python -X utf8 ip_sorgu.py 8.8.8.8
python -X utf8 ip_sorgu.py 1.1.1.1 --ip
python -X utf8 ip_sorgu.py google.com --whois
python -X utf8 ip_sorgu.py 192.168.1.1 --ip   # Yerel IP girilirse public IP otomatik bulunur
```

## Özellikler

- **Konum Bilgisi** — 3 farklı kaynaktan (ip-api.com, ipinfo.io, freeipapi.com) karşılaştırmalı geolocation
- **WHOIS** — IP için RIPE/ARIN'den yetkili sorgu, domain için kayıt bilgileri
- **Port Tarama** — 17 yaygın portu paralel olarak tarar (FTP, SSH, HTTP, HTTPS, RDP, MySQL vb.)
- **Yerel IP Tespiti** — 192.168.x.x gibi LAN IP girilince gerçek public IP otomatik bulunur

## Taranan Portlar

| Port | Servis  |
|------|---------|
| 21   | FTP     |
| 22   | SSH     |
| 23   | Telnet  |
| 25   | SMTP    |
| 53   | DNS     |
| 80   | HTTP    |
| 110  | POP3    |
| 143  | IMAP    |
| 443  | HTTPS   |
| 445  | SMB     |
| 3306 | MySQL   |
| 3389 | RDP     |
| 5432 | PostgreSQL |
| 6379 | Redis   |
| 8080 | HTTP-Alt |
| 8443 | HTTPS-Alt |
| 27017| MongoDB |
