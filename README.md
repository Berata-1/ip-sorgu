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
