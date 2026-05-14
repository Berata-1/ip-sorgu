import sys
import json
import socket
import urllib.request
import urllib.error
import io
import concurrent.futures
import whois

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Yaygın portlar: numara -> servis adı
YAYGIN_PORTLAR = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def baslik(metin: str) -> None:
    print()
    print("=" * 50)
    print(f"  {metin}")
    print("=" * 50)


def _fetch_json(url: str, timeout: int = 10) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ip-sorgu/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _whois_ulke_isp(ip: str) -> tuple[str, str]:
    """RIPE/ARIN WHOIS'ten yetkili ülke ve ISP bilgisini çeker."""
    try:
        sunucu = _ip_whois_sunucu(ip)
        metin = _ham_whois(sunucu, ip)
        for satir in metin.splitlines():
            if satir.strip().lower().startswith("referralserver:"):
                ref = satir.split(":", 1)[1].strip().replace("whois://", "")
                try:
                    metin = _ham_whois(ref, ip)
                except Exception:
                    pass
                break
        ulke = ""
        isp = ""
        for satir in metin.splitlines():
            if ":" not in satir or satir.startswith("%"):
                continue
            k, _, v = satir.partition(":")
            k, v = k.strip().lower(), v.strip()
            if not ulke and k == "country":
                ulke = v
            if not isp and k in ("netname", "descr", "orgname"):
                isp = v
        return ulke, isp
    except Exception:
        return "", ""


def ip_bilgisi(ip: str) -> None:
    baslik(f"IP Bilgisi: {ip}")

    # Kaynakları paralel çek
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(_fetch_json,
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
        f2 = ex.submit(_fetch_json, f"https://ipinfo.io/{ip}/json")
        f3 = ex.submit(_fetch_json, f"https://freeipapi.com/api/json/{ip}")
        f4 = ex.submit(_whois_ulke_isp, ip)
        d1, d2, d3 = f1.result(), f2.result(), f3.result()
        whois_ulke, whois_isp = f4.result()

    def satir(etiket: str, *degerler) -> None:
        goster = [str(d).strip() for d in degerler if d and str(d).strip() not in ("-", "")]
        benzersiz = list(dict.fromkeys(goster))
        if benzersiz:
            print(f"  {etiket:<16}: {' / '.join(benzersiz)}")

    # Ülke: WHOIS en yetkili kaynak, önce o
    ulke_1 = d1.get("country") if d1 and d1.get("status") == "success" else None
    ulke_2 = (d2 or {}).get("country")
    ulke_3 = (d3 or {}).get("countryName")
    satir("Ülke (WHOIS)",    whois_ulke)
    satir("Ülke (GeoIP)",    ulke_1, ulke_2, ulke_3)

    bolge_1 = d1.get("regionName") if d1 and d1.get("status") == "success" else None
    bolge_2 = (d2 or {}).get("region")
    bolge_3 = (d3 or {}).get("regionName")
    satir("Bölge *",         bolge_1, bolge_2, bolge_3)

    sehir_1 = d1.get("city") if d1 and d1.get("status") == "success" else None
    sehir_2 = (d2 or {}).get("city")
    sehir_3 = (d3 or {}).get("cityName")
    satir("Şehir *",         sehir_1, sehir_2, sehir_3)

    zip_1 = d1.get("zip") if d1 and d1.get("status") == "success" else None
    zip_2 = (d2 or {}).get("postal")
    satir("Posta Kodu",      zip_1, zip_2)

    loc = (d2 or {}).get("loc", "")
    lat_2, lon_2 = (loc.split(",") + [""])[:2] if "," in loc else ("", "")
    lat_1 = d1.get("lat") if d1 and d1.get("status") == "success" else None
    lon_1 = d1.get("lon") if d1 and d1.get("status") == "success" else None
    satir("Enlem",           lat_1, lat_2)
    satir("Boylam",          lon_1, lon_2)

    tz_1 = d1.get("timezone") if d1 and d1.get("status") == "success" else None
    tz_2 = (d2 or {}).get("timezone")
    satir("Saat Dilimi",     tz_1, tz_2)

    isp_1 = d1.get("isp") if d1 and d1.get("status") == "success" else None
    isp_2 = (d2 or {}).get("org")
    satir("ISP (WHOIS)",     whois_isp)
    satir("ISP (GeoIP)",     isp_1, isp_2)

    org_1 = d1.get("org") if d1 and d1.get("status") == "success" else None
    satir("AS",              org_1)

    print()
    print("  * Bölge/Şehir tahminidir; ISP'nin kayıt adresine göre farklı görünebilir.")
    print("=" * 50)


def _port_kontrol(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def port_tara(ip: str, timeout: float = 0.5) -> None:
    baslik(f"Port Tarama: {ip}")
    print(f"  Taranan port sayısı: {len(YAYGIN_PORTLAR)}")
    print()

    acik = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        gorevler = {
            executor.submit(_port_kontrol, ip, port, timeout): port
            for port in YAYGIN_PORTLAR
        }
        for gelecek in concurrent.futures.as_completed(gorevler):
            port, durum = gelecek.result()
            if durum:
                acik.append(port)

    if acik:
        for port in sorted(acik):
            servis = YAYGIN_PORTLAR.get(port, "?")
            print(f"  [AÇIK]  {port:<6} {servis}")
    else:
        print("  Taranan portların tamamı kapalı.")
    print("=" * 50)


def _ip_mi(hedef: str) -> bool:
    try:
        socket.inet_aton(hedef)
        return True
    except socket.error:
        return False


def _yerel_ip_mi(ip: str) -> bool:
    """192.168.x.x, 10.x.x.x, 172.16-31.x.x gibi özel aralıkları kontrol eder."""
    parcalar = ip.split(".")
    if len(parcalar) != 4:
        return False
    try:
        a, b = int(parcalar[0]), int(parcalar[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def public_ip_bul() -> str | None:
    """İnternete çıkış IP'sini üç farklı servisten bulmaya çalışır."""
    for url in [
        "https://api.ipify.org?format=json",
        "https://api4.my-ip.io/v2/ip.json",
        "https://ipinfo.io/json",
    ]:
        d = _fetch_json(url)
        if d:
            ip = d.get("ip") or d.get("IPv4")
            if ip:
                return ip.strip()
    return None


def _ham_whois(sunucu: str, sorgu: str, timeout: int = 10) -> str:
    with socket.create_connection((sunucu, 43), timeout=timeout) as s:
        s.sendall((sorgu + "\r\n").encode())
        yanit = b""
        while True:
            parca = s.recv(4096)
            if not parca:
                break
            yanit += parca
    return yanit.decode("utf-8", errors="replace")


def _ip_whois_sunucu(ip: str) -> str:
    # IANA'dan yetkili WHOIS sunucusunu bul
    yanit = _ham_whois("whois.iana.org", ip)
    for satir in yanit.splitlines():
        satir = satir.strip()
        if satir.lower().startswith("refer:"):
            return satir.split(":", 1)[1].strip()
    return "whois.arin.net"


def _ip_whois_ayrıstir(metin: str) -> dict:
    ilginc = {
        "netname": "Ağ Adı",
        "descr": "Açıklama",
        "country": "Ülke",
        "org": "Kuruluş",
        "orgname": "Kuruluş Adı",
        "organization": "Kuruluş",
        "address": "Adres",
        "cidr": "CIDR",
        "netrange": "IP Aralığı",
        "inetnum": "IP Aralığı",
        "route": "Rota",
        "origin": "AS Numarası",
        "mnt-by": "Yöneten",
        "abuse-mailbox": "Hata Bildirimi",
        "techphone": "Teknik Telefon",
    }
    sonuc = {}
    for satir in metin.splitlines():
        if ":" not in satir or satir.startswith("%") or satir.startswith("#"):
            continue
        anahtar, _, deger = satir.partition(":")
        anahtar = anahtar.strip().lower()
        deger = deger.strip()
        if anahtar in ilginc and deger and anahtar not in sonuc:
            sonuc[ilginc[anahtar]] = deger
    return sonuc


def whois_sorgula(hedef: str) -> None:
    baslik(f"WHOIS Bilgisi: {hedef}")

    if _ip_mi(hedef):
        # IP adresi için ham WHOIS sorgusu
        try:
            sunucu = _ip_whois_sunucu(hedef)
            metin = _ham_whois(sunucu, hedef)
            # ARIN referans yönlendirmesi varsa takip et
            for satir in metin.splitlines():
                if satir.strip().lower().startswith("referralserver:"):
                    ref = satir.split(":", 1)[1].strip().replace("whois://", "")
                    try:
                        metin = _ham_whois(ref, hedef)
                    except Exception:
                        pass
                    break
            veri = _ip_whois_ayrıstir(metin)
            if veri:
                for etiket, deger in veri.items():
                    print(f"  {etiket:<18}: {deger}")
            else:
                print("  Bu IP için WHOIS kaydı bulunamadı.")
        except Exception as e:
            print(f"  [HATA] WHOIS sorgusu başarısız: {e}")
    else:
        # Domain için python-whois kullan
        try:
            w = whois.whois(hedef)
            alanlar = [
                ("Domain Adı",       "domain_name"),
                ("Kayıt Kuruluşu",   "registrar"),
                ("Kayıt Tarihi",     "creation_date"),
                ("Bitiş Tarihi",     "expiration_date"),
                ("Güncellenme",      "updated_date"),
                ("Ad Sunucuları",    "name_servers"),
                ("Durum",            "status"),
                ("Ülke",             "country"),
                ("Sahip",            "org"),
                ("E-posta",          "emails"),
            ]
            for etiket, anahtar in alanlar:
                deger = getattr(w, anahtar, None)
                if not deger:
                    continue
                if isinstance(deger, list):
                    deger = deger[0] if len(deger) == 1 else ", ".join(str(d) for d in deger[:3])
                print(f"  {etiket:<16}: {deger}")
        except Exception as e:
            print(f"  [HATA] WHOIS sorgusu başarısız: {e}")

    print("=" * 50)


def yardim() -> None:
    print()
    print("Kullanım:")
    print("  python ip_sorgu.py <IP veya domain>             → Tam sorgu (IP + Port + WHOIS)")
    print("  python ip_sorgu.py <IP veya domain> --ip        → Sadece IP bilgisi")
    print("  python ip_sorgu.py <IP veya domain> --port      → Sadece port tarama")
    print("  python ip_sorgu.py <IP veya domain> --whois     → Sadece WHOIS bilgisi")
    print()
    print("Örnekler:")
    print("  python ip_sorgu.py 8.8.8.8")
    print("  python ip_sorgu.py google.com --whois")
    print("  python ip_sorgu.py 1.1.1.1 --port")
    print()


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        yardim()
        sys.exit(0)

    hedef = sys.argv[1].strip()
    mod = sys.argv[2].lower() if len(sys.argv) > 2 else "--tumu"

    # Domain ise önce IP'ye çevir
    try:
        ip = socket.gethostbyname(hedef)
    except socket.gaierror:
        ip = hedef

    # Yerel (LAN) IP girilmişse public IP'ye yönlendir
    if _yerel_ip_mi(ip):
        print(f"\n  [!] '{ip}' yerel ağ IP'sidir, geolocation yapılamaz.")
        print("  [*] Gerçek (public) IP'niz aranıyor...")
        public = public_ip_bul()
        if public:
            print(f"  [✓] Public IP'niz: {public}\n")
            hedef = public
            ip = public
        else:
            print("  [HATA] Public IP bulunamadı. İnternet bağlantınızı kontrol edin.")
            sys.exit(1)

    if mod == "--ip":
        ip_bilgisi(ip)
    elif mod == "--port":
        port_tara(ip)
    elif mod == "--whois":
        whois_sorgula(hedef)
    else:
        ip_bilgisi(ip)
        port_tara(ip)
        whois_sorgula(hedef)


if __name__ == "__main__":
    main()
