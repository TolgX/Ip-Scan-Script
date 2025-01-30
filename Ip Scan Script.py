import socket
import sys
from datetime import datetime
import threading
import time
from colorama import init, Fore, Back, Style
import platform
import nmap
import os
import requests
import random
from tqdm import tqdm
import json

# Colorama'yı başlat
init()

class AdvancedScanner:
    def __init__(self):
        self.hedef = None
        self.nm = nmap.PortScanner()
        self.timeout = 2
        self.sonuclar = {}

    def animate_banner(self):
        os.system('cls' if platform.system() == 'Windows' else 'clear')
        banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                   GELİŞMİŞ AĞ TARAMA ARACI                  ║
║                                                            ║
║  [1] Hızlı Tarama         [6] Versiyon Tespiti           ║
║  [2] Detaylı Port Tarama  [7] İşletim Sistemi Tespiti    ║
║  [3] Servis Tarama        [8] Script Tarama              ║
║  [4] UDP Tarama           [9] Firewall/IDS Tespiti       ║
║  [5] Agresif Tarama       [10] Çıkış                     ║
║                                                            ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""
        print(banner)

    def loading_animation(self, duration, text):
        with tqdm(total=100, desc=text, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            for i in range(100):
                time.sleep(duration/100)
                pbar.update(1)

    def print_result(self, title, result, color=Fore.GREEN):
        print(f"\n{color}{'=' * 60}")
        print(f" {title}")
        print('=' * 60)
        print(f"{result}{Style.RESET_ALL}")

    def hizli_tarama(self):
        print(f"\n{Fore.CYAN}[*] Hızlı tarama başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(2, "Tarama hazırlanıyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-F -T4')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host} ({self.nm[host].hostname()})\n"
                result += f"Durum : {self.nm[host].state()}\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
            
            self.print_result("HIZLI TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def detayli_port_tarama(self):
        print(f"\n{Fore.CYAN}[*] Detaylı port taraması başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(3, "Kapsamlı tarama hazırlanıyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-p- -T4')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
            
            self.print_result("DETAYLI PORT TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def servis_tarama(self):
        print(f"\n{Fore.CYAN}[*] Servis taraması başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(2.5, "Servisler analiz ediliyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-sV -T4')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        version = self.nm[host][proto][port].get('version', '')
                        result += f"Port : {port}\tDurum : {state}\tServis : {service}\tVersiyon : {version}\n"
            
            self.print_result("SERVİS TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)
            
    def udp_tarama(self):
        print(f"\n{Fore.CYAN}[*] UDP taraması başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(3, "UDP portları taranıyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-sU -T4 --top-ports 100')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
            
            self.print_result("UDP TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def agresif_tarama(self):
        print(f"\n{Fore.RED}[!] Agresif tarama başlatılıyor... (DİKKAT: Bu tarama tespit edilebilir!){Style.RESET_ALL}")
        self.loading_animation(4, "Agresif tarama yürütülüyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-A -T4 -v')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                if 'osclass' in self.nm[host]:
                    for osclass in self.nm[host]['osclass']:
                        result += f"OS Sınıfı : {osclass['osfamily']} ({osclass['accuracy']}%)\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        if 'script' in self.nm[host][proto][port]:
                            result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
                            for script in self.nm[host][proto][port]['script']:
                                result += f"  Script ({script}) : {self.nm[host][proto][port]['script'][script]}\n"
                        else:
                            result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
            
            self.print_result("AGRESİF TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def versiyon_tespiti(self):
        print(f"\n{Fore.CYAN}[*] Versiyon tespiti başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(3, "Servis versiyonları tespit ediliyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-sV --version-intensity 9')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                for proto in self.nm[host].all_protocols():
                    result += f"\nProtokol : {proto}\n"
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        version = self.nm[host][proto][port].get('version', 'Bilinmiyor')
                        product = self.nm[host][proto][port].get('product', 'Bilinmiyor')
                        result += f"Port : {port}\tDurum : {state}\tServis : {service}\n"
                        result += f"Ürün : {product}\tVersiyon : {version}\n"
            
            self.print_result("VERSİYON TESPİT SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def os_tespiti(self):
        print(f"\n{Fore.CYAN}[*] İşletim sistemi tespiti başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(2.5, "İşletim sistemi analiz ediliyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-O')
            result = ""
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        result += f"\nİşletim Sistemi : {osmatch['name']} (Doğruluk: {osmatch['accuracy']}%)\n"
                        if 'osclass' in osmatch:
                            for osclass in osmatch['osclass']:
                                result += f"OS Ailesi : {osclass['osfamily']}\n"
                                result += f"OS Nesli : {osclass['osgen']}\n"
                                result += f"Tip : {osclass['type']}\n"
            
            self.print_result("İŞLETİM SİSTEMİ TESPİT SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def script_tarama(self):
        print(f"\n{Fore.CYAN}[*] Script taraması başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(4, "Güvenlik scriptleri çalıştırılıyor")
        
        try:
            self.nm.scan(self.hedef, arguments='--script=vuln,auth,default,discovery,version')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        if 'script' in self.nm[host][proto][port]:
                            result += f"\nPort {port} ({self.nm[host][proto][port]['name']}) script sonuçları:\n"
                            for script_name, script_result in self.nm[host][proto][port]['script'].items():
                                result += f"\n{script_name}:\n"
                                formatted_result = script_result.replace('|', '\n  ').replace('  \n', '\n')
                                result += f"  {formatted_result}\n"
                                if 'VULNERABLE' in script_result:
                                    result += f"{Fore.RED}  [!] Güvenlik Açığı Tespit Edildi!{Style.RESET_ALL}\n"
            
            self.print_result("SCRIPT TARAMA SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def firewall_tespiti(self):
        print(f"\n{Fore.CYAN}[*] Firewall/IDS tespiti başlatılıyor...{Style.RESET_ALL}")
        self.loading_animation(3, "Güvenlik sistemleri analiz ediliyor")
        
        try:
            self.nm.scan(self.hedef, arguments='-sA -T4 -p 21,22,23,25,53,80,443,3306,3389,8080')
            result = ""
            for host in self.nm.all_hosts():
                result += f"\nHost : {host}\n"
                filtered_ports = []
                unfiltered_ports = []
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        if state == 'filtered':
                            filtered_ports.append(str(port))
                        else:
                            unfiltered_ports.append(str(port))
                
                result += "\nGüvenlik Sistemleri Analizi:\n"
                if filtered_ports:
                    result += f"\nFiltrelenen Portlar: {', '.join(filtered_ports)}"
                    result += "\n\nTespit Edilen Güvenlik Önlemleri:"
                    result += "\n- Stateful Firewall: Aktif"
                    if len(filtered_ports) > 5:
                        result += "\n- Paket Filtreleme: Güçlü"
                    else:
                        result += "\n- Paket Filtreleme: Temel Seviye"
                    
                    common_services = {
                        '80': 'HTTP',
                        '443': 'HTTPS',
                        '22': 'SSH',
                        '21': 'FTP',
                        '3389': 'RDP',
                        '8080': 'HTTP-Proxy'
                    }
                    
                    result += "\n\nÖnemli Servis Durumları:"
                    for port, service in common_services.items():
                        if port in filtered_ports:
                            result += f"\n- {service} (Port {port}): Filtreleniyor"
                else:
                    result += "\nHiçbir port filtrelenmemiş."
                    result += "\nMuhtemel Durumlar:"
                    result += "\n- Firewall kapalı olabilir"
                    result += "\n- Firewall bypass edilmiş olabilir"
                    result += "\n- Host kapalı olabilir"
                
                result += "\n\nGüvenlik Önerileri:"
                if not filtered_ports:
                    result += "\n- Güvenlik duvarı yapılandırması önerilir"
                    result += "\n- Kritik portlar için erişim kontrolü yapılandırılmalı"
                elif len(filtered_ports) < 5:
                    result += "\n- Güvenlik duvarı kuralları güçlendirilmeli"
                    result += "\n- Daha fazla port için filtreleme eklenebilir"
                else:
                    result += "\n- Mevcut güvenlik önlemleri yeterli görünüyor"
                    result += "\n- Düzenli güvenlik testleri ile kontrol edilmeli"
                
            self.print_result("FIREWALL/IDS TESPİT SONUÇLARI", result)
            
        except Exception as e:
            self.print_result("HATA", str(e), Fore.RED)

    def run(self):
        while True:
            self.animate_banner()
            secim = input(f"\n{Fore.YELLOW}[?] Seçiminizi yapın (1-10): {Style.RESET_ALL}")
            
            if secim == '10':
                print(f"\n{Fore.GREEN}[*] Program sonlandırılıyor...{Style.RESET_ALL}")
                break
                
            if secim not in ['1', '2', '3', '4', '5', '6', '7', '8', '9']:
                print(f"{Fore.RED}[!] Geçersiz seçim!{Style.RESET_ALL}")
                continue
                
            self.hedef = input(f"\n{Fore.YELLOW}[?] Hedef IP adresini girin: {Style.RESET_ALL}")
            
            if secim == '1':
                self.hizli_tarama()
            elif secim == '2':
                self.detayli_port_tarama()
            elif secim == '3':
                self.servis_tarama()
            elif secim == '4':
                self.udp_tarama()
            elif secim == '5':
                self.agresif_tarama()
            elif secim == '6':
                self.versiyon_tespiti()
            elif secim == '7':
                self.os_tespiti()
            elif secim == '8':
                self.script_tarama()
            elif secim == '9':
                self.firewall_tespiti()
            
            input(f"\n{Fore.YELLOW}[*] Devam etmek için Enter'a basın...{Style.RESET_ALL}")

def main():
    try:
        scanner = AdvancedScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Program kullanıcı tarafından sonlandırıldı.{Style.RESET_ALL}")
        sys.exit()
    except Exception as e:
        print(f"\n{Fore.RED}[!] Bir hata oluştu: {e}{Style.RESET_ALL}")
        sys.exit()

if __name__ == "__main__":
    main()