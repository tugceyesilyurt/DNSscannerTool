import dns.resolver
import socket
import dns.query
import dns.message
import dns.flags
import dns.exception
import dns.zone
import time
from flask import Flask, render_template_string, request

app = Flask(__name__)

def get_ns_servers(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        answers = resolver.resolve(domain, 'NS')
        ns_servers = [str(rdata.target).rstrip('.') for rdata in answers]
        return ns_servers
    except Exception:
        return []

def get_ns_ip(ns_server):
    try:
        return socket.gethostbyname(ns_server)
    except Exception:
        return None

def check_dns_recursion(ns_ip):
    try:
        query = dns.message.make_query('google.com', dns.rdatatype.A)
        response = dns.query.udp(query, ns_ip, timeout=3)
        return bool(response.flags & dns.flags.RA)
    except Exception:
        return None

def check_zone_transfer(ns_ip, domain):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
        if zone:
            allowed_types = {dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.NS, dns.rdatatype.MX, dns.rdatatype.CNAME}
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
    except Exception:
        return None

def check_dns_version_disclosure(ns_ip):
    try:
        query = dns.message.make_query('version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        response = dns.query.udp(query, ns_ip, timeout=3)
        for answer in response.answer:
            for item in answer.items:
                return item.to_text().strip('"')
        return None
    except Exception:
        return None

def check_dnssec_support(ns_ip, domain):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
        response = dns.query.udp(query, ns_ip, timeout=3)
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.DNSKEY:
                return True
        query_rrsig = dns.message.make_query(domain, dns.rdatatype.RRSIG)
        response_rrsig = dns.query.udp(query_rrsig, ns_ip, timeout=3)
        for answer in response_rrsig.answer:
            if answer.rdtype == dns.rdatatype.RRSIG:
                return True
        return False
    except Exception:
        return None

def check_tcp_port_open(ns_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ns_ip, 53))
        sock.close()
        return result == 0
    except Exception:
        return None

def check_any_query_support(ns_ip, domain):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.ANY)
        response = dns.query.tcp(query, ns_ip, timeout=3)
        if response.answer:
            records = []
            for answer in response.answer:
                for item in answer.items:
                    records.append(answer.to_text())
            return records
        else:
            return False
    except Exception:
        return None

def wildcard_dns_test(domain):
    results = []
    found = False
    for i in range(3):
        fake_subdomain = f"nonexistent{i}-{int(time.time())}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 3
            resolver.lifetime = 5
            answer = resolver.resolve(fake_subdomain, 'A')
            if answer.rrset is not None and len(answer) > 0:
                for rdata in answer:
                    results.append(f"[!!] Wildcard DNS VAR: {fake_subdomain} → {rdata.to_text()}")
                found = True
            else:
                results.append(f"[✓] YOK (Boş cevap): {fake_subdomain}")
        except dns.resolver.NXDOMAIN:
            results.append(f"[✓] Wildcard DNS YOK: {fake_subdomain} → NXDOMAIN")
        except dns.resolver.NoAnswer:
            results.append(f"[✓] Wildcard DNS YOK: {fake_subdomain} → NoAnswer")
        except dns.resolver.Timeout:
            results.append(f"[!] Zaman aşımı: {fake_subdomain} → Timeout")
        except Exception as e:
            results.append(f"[!] HATA: {fake_subdomain} → {e}")
    if not found:
        results.append("→ Wildcard DNS tespit edilemedi.")
    return results

def open_resolver_test(ns_ip_map):
    results = []
    results.append("\nOpen Resolver Testi Başlatıldı:")
    for ns, ip in ns_ip_map.items():
        try:
            query = dns.message.make_query("idonotexist987654321.com", dns.rdatatype.A)
            response = dns.query.udp(query, ip, timeout=3)
            if response.flags & dns.flags.RA:
                results.append(f"[!!] Open Resolver TESPİT EDİLDİ: {ns} ({ip}) → Recursion aktif!")
            else:
                results.append(f"[✓] Open Resolver DEĞİL: {ns} ({ip}) → Recursion pasif")
        except Exception as e:
            results.append(f"[✓] Open Resolver DEĞİL: {ns} ({ip}) — {e}")
    return results

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

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>DNS Güvenlik Tarayıcı Web</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 900px; margin: 30px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px #aaa; }
        h1 { color: #2c3e50; }
        textarea { width: 100%; height: 400px; font-family: Consolas, monospace; font-size: 13px; margin-top: 10px; }
        .btn { padding: 10px 20px; background: #2980b9; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #3498db; }
        label { font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Güvenlik Tarayıcı Web</h1>
        <form method="post">
            <label>Domain:</label>
            <input type="text" name="domain" value="{{ domain }}" style="width:300px; font-size:15px;" required>
            <button class="btn" type="submit">Tara</button>
        </form>
        <textarea readonly>{{ result }}</textarea>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    domain = ''
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        if not domain:
            result = 'Lütfen bir domain girin.'
        else:
            result += f"-> {domain} için güvenlik taraması başlatıldı...\n" + "-"*50 + "\n"
            ns_sunuculari = get_ns_servers(domain)
            ns_ip_map = {}
            if ns_sunuculari:
                for server in ns_sunuculari:
                    result += "-" * 50 + "\n"
                    ip = get_ns_ip(server)
                    if ip:
                        ns_ip_map[server] = ip
                        recursion = check_dns_recursion(ip)
                        if recursion is None:
                            durum = "Recursion kontrolü yapılamadı"
                        elif recursion:
                            durum = "GÜVENLİK AÇIĞI: Recursion açık!"
                        else:
                            durum = "Güvenli (Recursion kapalı)"
                        result += f"Sunucu: {server} ({ip})\n  - Recursion Durumu: {durum}\n"

                        axfr_vuln = check_zone_transfer(ip, domain)
                        if axfr_vuln is None:
                            axfr_durum = "Kontrol edilemedi."
                        elif isinstance(axfr_vuln, list):
                            axfr_durum = "GÜVENLİK AÇIĞI: Zone Transfer (AXFR) aktif!\n" + format_zone_transfer_output(domain, ip, axfr_vuln)
                        elif axfr_vuln:
                            axfr_durum = "GÜVENLİK AÇIĞI: Zone Transfer (AXFR) aktif! (Kayıtlar alınamadı)"
                        else:
                            axfr_durum = "Güvenli (Zone Transfer kapalı)"
                        result += f"  - Zone Transfer Durumu: {axfr_durum}\n"

                        version_info = check_dns_version_disclosure(ip)
                        if version_info and version_info.lower() not in ["it's a secret", "unknown"]:
                            result += f"  - DNS Sürüm Bilgisi: GÜVENLİK AÇIĞI! (Sızan bilgi: {version_info})\n"
                        else:
                            result += f"  - DNS Sürüm Bilgisi: Güvenli (Sürüm bilgisi gizli)\n"

                        dnssec = check_dnssec_support(ip, domain)
                        if dnssec is None:
                            dnssec_durum = "Kontrol edilemedi."
                        elif dnssec:
                            dnssec_durum = "Destekleniyor (Güvenli)"
                        else:
                            dnssec_durum = "GÜVENLİK AÇIĞI: DNSSEC desteklenmiyor!"
                        result += f"  - DNSSEC Desteği: {dnssec_durum}\n"

                        tcp53 = check_tcp_port_open(ip)
                        if tcp53 is None:
                            tcp53_durum = "Kontrol edilemedi."
                        elif tcp53:
                            tcp53_durum = "Açık (Güvenli)"
                        else:
                            tcp53_durum = "GÜVENLİK AÇIĞI: TCP 53 kapalı!"
                        result += f"  - TCP 53 Durumu: {tcp53_durum}\n"

                        any_support = check_any_query_support(ip, domain)
                        if any_support is None:
                            any_durum = "Kontrol edilemedi."
                        elif isinstance(any_support, list):
                            any_durum = "GÜVENLİK AÇIĞI: ANY sorgusuna cevap veriyor!\nCevaplanan Kayıtlar:\n" + "\n".join(any_support)
                        elif any_support:
                            any_durum = "GÜVENLİK AÇIĞI: ANY sorgusuna cevap veriyor! (Kayıtlar alınamadı)"
                        else:
                            any_durum = "Güvenli (ANY sorgusu kısıtlı)"
                        result += f"  - ANY Sorgusu Desteği: {any_durum}\n"
                    else:
                        result += f"Sunucu: {server} (IP adresi alınamadı)\n"
                result += "-" * 50 + "\n"
            else:
                result += f"\n{domain} için NS sunucusu bulunamadı veya bir hata oluştu.\n"

            result += "\n" + "="*50 + "\n[Open Resolver Testi Sonucu]\n" + "="*50 + "\n"
            open_resolver_results = open_resolver_test(ns_ip_map)
            for line in open_resolver_results:
                result += line + "\n"

            result += "\n" + "="*50 + "\n[Wildcard DNS Testi Sonucu]\n" + "="*50 + "\n"
            wildcard_results = wildcard_dns_test(domain)
            for line in wildcard_results:
                result += line + "\n"
            result += "\nTarama tamamlandı.\n"
    return render_template_string(HTML_TEMPLATE, result=result, domain=domain)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
