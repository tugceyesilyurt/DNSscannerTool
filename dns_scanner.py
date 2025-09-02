import dns.resolver  # NS, A, MX gibi kayıtları çözer
import socket # Hostname → IP, TCP port kontrolü
import dns.query #  DNS sorgusunu göndermek (UDP/TCP)
import dns.message # DNS sorgu paketi oluşturur
import dns.flags # Cevaptaki flag’leri yorumlar (RA, RD vs.)
import dns.exception # DNS hatalarını kontrol altına alır
import dns.zone # AXFR sonucu gelen zone'u anlamlı nesne yapar
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading

def get_ns_servers(domain): #1. recursion kontrolü için NS sunucu adlarını bulur
    """
    Verilen bir domain'in NS (Name Server) kayıtlarını döndürür.
    DNS sorguları Google DNS (8.8.8.8) üzerinden yapılır.
    """
    try:
        resolver = dns.resolver.Resolver()#DNS sorguları için resolver oluşturulur.
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']#Google DNS kullanılır.
        answers = resolver.resolve(domain, 'NS')#NS kayıtlarını alır.
        ns_servers = [str(rdata.target).rstrip('.') for rdata in answers]#NS sunucu adlarını alır.  
        return ns_servers
    except dns.resolver.NoAnswer: #NS kayıtları bulunamadı.
        print(f"Hata: {domain} için NS kaydı bulunamadı.")
        return []
    except dns.resolver.NXDOMAIN: #Domain mevcut değil.
        print(f"Hata: {domain} adresi mevcut değil.")
        return []
    except Exception as e: #Beklenmedik bir hata oluştu.    
        print(f"Beklenmedik bir hata oluştu: {e}")
        return []

def get_ns_ip(ns_server):#NS sunucu adını alıp IP adresini döndürür.
    """
    NS sunucu adını alıp IP adresini döndürür.
    """
    try:
        return socket.gethostbyname(ns_server)#NS sunucu adını alıp IP adresini döndürür.
    except Exception as e:
        print(f"{ns_server} için IP alınamadı: {e}")
        return None

def check_dns_recursion(ns_ip):#Verilen NS sunucusunda recursion açık mı kontrol eder.  
    """
    Verilen NS sunucusunda recursion açık mı kontrol eder.
    Açık ise True, kapalı ise False, hata olursa None döner.
    """
    try:
        # İlgisiz bir domain için recursive sorgu gönderiyoruz
        query = dns.message.make_query('google.com', dns.rdatatype.A)
        response = dns.query.udp(query, ns_ip, timeout=3)
        if response.flags & dns.flags.RA:
            return True
        else:
            return False
    except Exception as e:
        print(f"{ns_ip} için recursion kontrolü yapılamadı: {e}")
        return None

def check_zone_transfer(ns_ip, domain):#2. Verilen NS sunucusunda Zone Transfer (AXFR)  yapmaya izin verip vermediğini kontrol eder.
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
        if zone:
            # Sadece A, AAAA, NS, MX, CNAME kayıtlarını ekle, veri 100 karakterden uzunsa atla
            allowed_types = {
                dns.rdatatype.A,
                dns.rdatatype.AAAA,
                dns.rdatatype.NS,
                dns.rdatatype.MX,
                dns.rdatatype.CNAME
            }
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    if rdataset.rdtype in allowed_types:
                        for rdata in rdataset:
                            rdata_str = str(rdata)
                            if len(rdata_str) <= 100:
                                records.append(f"{name}.{domain} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata_str}")
            return records
        else:
            return False
    except dns.exception.FormError:
        return False
    except dns.exception.Timeout:
        return False
    except Exception as e:
        print(f"    [!] Zone Transfer hatası: {e}")
        return None

def check_dns_version_disclosure(ns_ip):#3. DNS sunucusunun version.bind (CHAOS class) sorgusuna cevap verip vermediğini kontrol eder.sürüm bilgisi öğrenmek için
   #Hedef: IP adresi verilen bir DNS sunucusuna version.bind sorgusu gönderip cevap alabiliyor muyuz
    try:
        # CHAOS(CH) sınıfında 'version.bind' için özel bir TXT sorgusu hazırlanır.
        query = dns.message.make_query('version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        # Sorgu, ns_ip adresindeki DNS sunucusuna UDP ile gönderiliyor
        response = dns.query.udp(query, ns_ip, timeout=3) #
        for answer in response.answer:
            for item in answer.items:
                return item.to_text().strip('"')
        return None
    except Exception:
        return None

def check_dnssec_support(ns_ip, domain):#4.Verilen NS sunucusunda DNSSEC desteği olup olmadığını kontrol eder.
    
    try:
        query = dns.message.make_query(domain, dns.rdatatype.DNSKEY)#Bana bu domain’in açık anahtarlarını (DNSKEY) ver.
        response = dns.query.udp(query, ns_ip, timeout=3)#Sorgu gönderilir, cevap beklenir
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.DNSKEY:
                # DNSKEY varsa, DNSSEC destekleniyor olabilir
                return True
        # DNSKEY yoksa Ek olarak RRSIG(imza) kaydı var mı bak
        query_rrsig = dns.message.make_query(domain, dns.rdatatype.RRSIG)
        response_rrsig = dns.query.udp(query_rrsig, ns_ip, timeout=3)#RRAIG cevabı alınır
        for answer in response_rrsig.answer:
            if answer.rdtype == dns.rdatatype.RRSIG:#RRSIG cevabı varsa → DNSSEC aktif demektir
                return True
        return False
    except Exception as e:
        print(f"{ns_ip} için DNSSEC kontrolü yapılamadı: {e}")
        return None

def check_tcp_port_open(ns_ip):#5.NS sunucusunda TCP port 53 açık mı kontrol eder.
   #Bir TCP soketi oluşturur, AF_INET → IPv4 adresleme, SOCK_STREAM → TCP bağlantısı
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ns_ip, 53))#IP adresine, TCP port 53 üzerinden bağlantı denemesi yapılır.
        sock.close()
        if result == 0: #connect_ex 0 dönerse port açık
            return True
        else:
            return False
    except Exception as e:
        print(f"{ns_ip} için TCP port kontrolü yapılamadı: {e}")
        return None

def check_any_query_support(ns_ip, domain):#6.NS sunucusu ANY sorgusuna cevap veriyor mu kontrol eder.
    
    try:
        query = dns.message.make_query(domain, dns.rdatatype.ANY)#domain için, tüm kayıtları isteyen bir DNS sorgusu hazırlanır.
        response = dns.query.udp(query, ns_ip, timeout=3)#Hazırlanan sorgu, IP adresine UDP ile gönderilir süre 3sn
        if response.answer:
            # Dönen kayıtları topla
            records = []
            for answer in response.answer:
                for item in answer.items:
                    records.append(answer.to_text())
            return records  # Liste olarak döndür
        else:
            return False
    except Exception as e:
        print(f"{ns_ip} için ANY sorgusu kontrolü yapılamadı: {e}")
        return None

def yazdir_ve_kaydet(metin, dosya):#Metni ekrana yazdırır ve rapora kaydeder.   
    print(metin)
    dosya.write(metin + '\n')

def format_zone_transfer_output(domain, ns_ip, records):
    import datetime
    output = []
    output.append(f';; Zone transfer for {domain} from {ns_ip}')
    output.append(';; ANSWER SECTION:')
    for record in records:
        output.append(record)
    output.append('')
    output.append(f';; Query time: N/A msec')
    output.append(f';; SERVER: {ns_ip}#53 ({ns_ip}) (TCP)')
    output.append(f';; WHEN: {datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")}')
    output.append(f';; MSG SIZE  rcvd: {sum(len(r) for r in records)}')
    return '\n'.join(output)

def gui_ile_tara():
    domain = entry.get().strip()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin!")
        return

    tara_buton.config(state=tk.DISABLED)
    kaydet_buton.config(state=tk.DISABLED)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"-> {domain} için güvenlik taraması başlatıldı...\n" + "-"*50 + "\n")

    ns_sunuculari = get_ns_servers(domain)
    if ns_sunuculari:
        for server in ns_sunuculari:
            output_text.insert(tk.END, "-" * 50 + "\n")
            ip = get_ns_ip(server)
            if ip:
                # Recursion Kontrolü
                recursion = check_dns_recursion(ip)
                if recursion is None:
                    durum = "Recursion kontrolü yapılamadı"
                elif recursion:
                    durum = "GÜVENLİK AÇIĞI: Recursion açık!"
                else:
                    durum = "Güvenli (Recursion kapalı)"
                output_text.insert(tk.END, f"Sunucu: {server} ({ip})\n  - Recursion Durumu: {durum}\n")

                # Zone Transfer Kontrolü
                axfr_vuln = check_zone_transfer(ip, domain)
                if axfr_vuln is None:
                    axfr_durum = "Kontrol edilemedi."
                elif isinstance(axfr_vuln, list):
                    axfr_durum = "GÜVENLİK AÇIĞI: Zone Transfer (AXFR) aktif!\n" + format_zone_transfer_output(domain, ip, axfr_vuln)
                elif axfr_vuln:
                    axfr_durum = "GÜVENLİK AÇIĞI: Zone Transfer (AXFR) aktif! (Kayıtlar alınamadı)"
                else:
                    axfr_durum = "Güvenli (Zone Transfer kapalı)"
                output_text.insert(tk.END, f"  - Zone Transfer Durumu: {axfr_durum}\n")

                # Version Disclosure Kontrolü
                version_info = check_dns_version_disclosure(ip)
                if version_info and version_info.lower() not in ["it's a secret", "unknown"]:
                    output_text.insert(tk.END, f"  - DNS Sürüm Bilgisi: GÜVENLİK AÇIĞI! (Sızan bilgi: {version_info})\n")
                else:
                    output_text.insert(tk.END, f"  - DNS Sürüm Bilgisi: Güvenli (Sürüm bilgisi gizli)\n")

                # DNSSEC Desteği Kontrolü
                dnssec = check_dnssec_support(ip, domain)
                if dnssec is None:
                    dnssec_durum = "Kontrol edilemedi."
                elif dnssec:
                    dnssec_durum = "Destekleniyor (Güvenli)"
                else:
                    dnssec_durum = "GÜVENLİK AÇIĞI: DNSSEC desteklenmiyor!"
                output_text.insert(tk.END, f"  - DNSSEC Desteği: {dnssec_durum}\n")

                # TCP Port 53 Açık mı?
                tcp53 = check_tcp_port_open(ip)
                if tcp53 is None:
                    tcp53_durum = "Kontrol edilemedi."
                elif tcp53:
                    tcp53_durum = "Açık (Güvenli)"
                else:
                    tcp53_durum = "GÜVENLİK AÇIĞI: TCP 53 kapalı!"
                output_text.insert(tk.END, f"  - TCP 53 Durumu: {tcp53_durum}\n")

                # ANY Sorgusu Desteği
                any_support = check_any_query_support(ip, domain)
                if any_support is None:
                    any_durum = "Kontrol edilemedi."
                elif isinstance(any_support, list):
                    any_durum = "GÜVENLİK AÇIĞI: ANY sorgusuna cevap veriyor!\nCevaplanan Kayıtlar:\n" + "\n".join(any_support)
                elif any_support:
                    any_durum = "GÜVENLİK AÇIĞI: ANY sorgusuna cevap veriyor! (Kayıtlar alınamadı)"
                else:
                    any_durum = "Güvenli (ANY sorgusu kısıtlı)"
                output_text.insert(tk.END, f"  - ANY Sorgusu Desteği: {any_durum}\n")
            else:
                output_text.insert(tk.END, f"Sunucu: {server} (IP adresi alınamadı)\n")
        output_text.insert(tk.END, "-" * 50 + "\n")
    else:
        output_text.insert(tk.END, f"\n{domain} için NS sunucusu bulunamadı veya bir hata oluştu.\n")
    tara_buton.config(state=tk.NORMAL)
    kaydet_buton.config(state=tk.NORMAL)

def gui_ile_tara_thread():
    threading.Thread(target=gui_ile_tara).start()

def kaydet():
    rapor = output_text.get(1.0, tk.END)
    dosya_adi = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Metin Dosyası", "*.txt")])
    if dosya_adi:
        with open(dosya_adi, "w", encoding="utf-8") as f:
            f.write(rapor)
        messagebox.showinfo("Başarılı", "Rapor başarıyla kaydedildi.")

# Tkinter arayüzü
pencere = tk.Tk()
pencere.title("DNS Güvenlik Tarayıcı Projesi")
pencere.geometry("800x600")
pencere.resizable(False, False)

# Başlık ve açıklama
header = tk.Label(pencere, text="DNS Güvenlik Tarayıcı", font=("Arial", 16, "bold"))
header.pack(pady=5)
desc = tk.Label(pencere, text="Bir domain girin ve DNS güvenlik açıklarını tarayın.", font=("Arial", 10))
desc.pack(pady=2)

# Domain giriş kutusu
frame = tk.Frame(pencere)
frame.pack(pady=5)
entry = tk.Entry(frame, width=40, font=("Arial", 12))
entry.pack(side=tk.LEFT, padx=5)
entry.insert(0, "example.com")  # Placeholder gibi başlangıç değeri

tara_buton = tk.Button(frame, text="Tara", width=10, command=gui_ile_tara_thread)
tara_buton.pack(side=tk.LEFT, padx=5)

kaydet_buton = tk.Button(frame, text="Raporu Kaydet", width=15, command=kaydet)
kaydet_buton.pack(side=tk.LEFT, padx=5)

output_text = scrolledtext.ScrolledText(pencere, width=95, height=28, font=("Consolas", 10))
output_text.pack(padx=10, pady=10)

pencere.mainloop() 