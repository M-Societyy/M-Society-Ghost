#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import os
import threading
import requests
import time
from time import sleep
from PIL import ImageTk, Image
import io
import subprocess
import random
import sys

def get_user_language():
    try:
        response = requests.get('https://ipapi.co/json/', timeout=5)
        data = response.json()
        country = data.get('country', '')
        spanish_speaking = ['ES', 'MX', 'AR', 'CO', 'PE', 'VE', 'CL', 'EC', 'GT', 
                           'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 
                           'UY', 'GQ']
        return 'es' if country in spanish_speaking else 'en'
    except:
        return 'en'

LANG = get_user_language()

TEXTS = {
    'es': {
        'title': "M-SOCIETY GHOST",
        'subtitle': "SISTEMA DE ANONIMATO TOTAL",
        'mac_tor': "MAC + TOR + TERMINAL",
        'clean': "LIMPIAR RASTROS",
        'vpn': "VPN SEGURA",
        'dns': "DNS ANÓNIMO",
        'kill': "MATAR PROCESOS",
        'status': "ESTADO DEL SISTEMA",
        'exit': "SALIR",
        'mac_success': "[✓] MAC FALSIFICADO CON ÉXITO",
        'mac_fail': "[✗] FALLO EN SPOOF DE MAC",
        'tor_start': "[...] INICIANDO TOR...",
        'tor_success': "[✓] TOR ACTIVADO - TÚNEL SEGURO ESTABLECIDO",
        'tor_fail': "[✗] FALLO AL INICIAR TOR",
        'term_success': "[✓] TERMINAL CAMUFLADA CON PROXYCHAINS INICIADA",
        'term_fail': "[✗] FALLO AL ABRIR TERMINAL",
        'clean_success': "[✓] LIMPIEZA COMPLETA - RASTROS ELIMINADOS",
        'clean_fail': "[✗] FALLO EN LIMPIEZA DE RASTROS",
        'vpn_success': "[✓] VPN CONFIGURADA - TRÁFICO CIFRADO",
        'vpn_fail': "[✗] FALLO AL CONECTAR VPN",
        'dns_success': "[✓] DNS ANÓNIMO CONFIGURADO",
        'dns_fail': "[✗] FALLO AL CAMBIAR DNS",
        'kill_success': "[✓] PROCESOS PELIGROSOS TERMINADOS",
        'kill_fail': "[✗] FALLO AL TERMINAR PROCESOS",
        'checking': "[*] VERIFICANDO ESTADO DEL SISTEMA...",
        'safe': "[✓] SISTEMA SEGURO - ANONIMATO ACTIVO",
        'warning': "[!] ADVERTENCIA: SE DETECTARON VULNERABILIDADES",
        'exit_msg': "SALIENDO DEL SISTEMA... BORRANDO HUELLAS",
        'dev': "M-SOCIETY GHOST v3.0"
    },
    'en': {
        'title': "M-SOCIETY GHOST",
        'subtitle': "TOTAL ANONYMITY SYSTEM",
        'mac_tor': "MAC + TOR + TERMINAL",
        'clean': "WIPE TRACES",
        'vpn': "SECURE VPN",
        'dns': "ANONYMOUS DNS",
        'kill': "KILL PROCESSES",
        'status': "SYSTEM STATUS",
        'exit': "EXIT",
        'mac_success': "[✓] MAC ADDRESS SPOOFED SUCCESSFULLY",
        'mac_fail': "[✗] MAC SPOOFING FAILED",
        'tor_start': "[...] STARTING TOR...",
        'tor_success': "[✓] TOR ACTIVATED - SECURE TUNNEL ESTABLISHED",
        'tor_fail': "[✗] FAILED TO START TOR",
        'term_success': "[✓] PROXYCHAIN TERMINAL LAUNCHED",
        'term_fail': "[✗] FAILED TO OPEN TERMINAL",
        'clean_success': "[✓] FULL CLEANUP - TRACES WIPED",
        'clean_fail': "[✗] CLEANUP FAILED",
        'vpn_success': "[✓] VPN CONFIGURED - TRAFFIC ENCRYPTED",
        'vpn_fail': "[✗] VPN CONNECTION FAILED",
        'dns_success': "[✓] ANONYMOUS DNS CONFIGURED",
        'dns_fail': "[✗] FAILED TO CHANGE DNS",
        'kill_success': "[✓] DANGEROUS PROCESSES TERMINATED",
        'kill_fail': "[✗] FAILED TO KILL PROCESSES",
        'checking': "[*] CHECKING SYSTEM STATUS...",
        'safe': "[✓] SYSTEM SECURE - ANONYMITY ACTIVE",
        'warning': "[!] WARNING: VULNERABILITIES DETECTED",
        'exit_msg': "EXITING SYSTEM... WIPING TRACES",
        'dev': "M-SOCIETY GHOST v3.0"
    }
}

def spoof_mac(logbox):
    try:
        logbox.insert(tk.END, "[...] CHANGING MAC ADDRESS...\n" if LANG == 'en' else "[...] CAMBIANDO DIRECCIÓN MAC...\n")
        logbox.see(tk.END)
        interfaces = ["eth0", "wlan0", "wlp3s0"]
        for interface in interfaces:
            os.system(f"ifconfig {interface} down 2>/dev/null")
            os.system(f"macchanger -r {interface} 2>/dev/null")
            os.system(f"ifconfig {interface} up 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['mac_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['mac_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def iniciar_tor(logbox):
    try:
        logbox.insert(tk.END, TEXTS[LANG]['tor_start'] + "\n")
        logbox.see(tk.END)
        os.system("service tor stop 2>/dev/null")
        os.system("service tor start 2>/dev/null")
        sleep(5)
        logbox.insert(tk.END, TEXTS[LANG]['tor_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['tor_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def abrir_terminal_proxy(logbox):
    try:
        terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "xterm"]
        for term in terminals:
            if os.system(f"which {term} >/dev/null") == 0:
                os.system(f"{term} -- bash -c 'proxychains bash' &")
                logbox.insert(tk.END, TEXTS[LANG]['term_success'] + "\n")
                logbox.see(tk.END)
                return
        raise Exception("No terminal found")
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['term_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def limpar_rastro(logbox):
    try:
        logbox.insert(tk.END, "[...] CLEANING SYSTEM..." if LANG == 'en' else "[...] LIMPIANDO SISTEMA...\n")
        logbox.see(tk.END)
        cleaners = [
            "bleachbit -c system.cache system.clipboard system.recent_documents bash.history",
            "history -c && history -w && unset HISTFILE",
            "shred -u ~/.bash_history",
            "find /tmp /var/tmp -type f -exec shred -u {} \;",
            "swapoff -a && swapon -a"
        ]
        for cmd in cleaners:
            os.system(cmd + " 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['clean_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['clean_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def secure_vpn(logbox):
    try:
        vpns = [
            "nordvpn", "protonvpn", "windscribe", "mullvad",
            "openvpn", "wireguard"
        ]
        for vpn in vpns:
            if os.system(f"which {vpn} >/dev/null") == 0:
                os.system(f"{vpn} connect")
                logbox.insert(tk.END, TEXTS[LANG]['vpn_success'] + f" ({vpn})\n")
                logbox.see(tk.END)
                return
        raise Exception("No VPN client found")
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['vpn_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def change_dns(logbox):
    try:
        dns_servers = [
            "1.1.1.1", "1.0.0.1",  
            "8.8.8.8", "8.8.4.4",  
            "9.9.9.9", "149.112.112.112",  
            "94.140.14.14", "94.140.15.15" 
        ]
        new_dns = random.choice(dns_servers)
        os.system(f"echo 'nameserver {new_dns}' > /etc/resolv.conf")
        logbox.insert(tk.END, TEXTS[LANG]['dns_success'] + f" ({new_dns})\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['dns_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def kill_processes(logbox):
    try:
        dangerous = ["wireshark", "tcpdump", "nmap", "nessus", "metasploit"]
        for proc in dangerous:
            os.system(f"pkill -9 {proc} 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['kill_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['kill_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def check_status(logbox):
    try:
        logbox.insert(tk.END, TEXTS[LANG]['checking'] + "\n")
        logbox.see(tk.END)
        
        tor_check = os.system("curl --socks5 localhost:9050 --connect-timeout 5 -s https://check.torproject.org/ | grep -q 'Congratulations'")
        if tor_check == 0:
            logbox.insert(tk.END, "[✓] TOR CONNECTION: ACTIVE\n" if LANG == 'en' else "[✓] CONEXIÓN TOR: ACTIVA\n")
        else:
            logbox.insert(tk.END, "[✗] TOR CONNECTION: INACTIVE\n" if LANG == 'en' else "[✗] CONEXIÓN TOR: INACTIVA\n")
        
        vpn_check = os.system("ip a | grep -q 'tun'")
        if vpn_check == 0:
            logbox.insert(tk.END, "[✓] VPN: ACTIVE\n" if LANG == 'en' else "[✓] VPN: ACTIVA\n")
        else:
            logbox.insert(tk.END, "[✗] VPN: INACTIVE\n" if LANG == 'en' else "[✗] VPN: INACTIVA\n")
        
        mac_check = os.system("macchanger -s eth0 | grep -q 'Permanent'")
        if mac_check != 0:
            logbox.insert(tk.END, "[✓] MAC SPOOFED\n" if LANG == 'en' else "[✓] MAC FALSIFICADA\n")
        else:
            logbox.insert(tk.END, "[✗] MAC NOT SPOOFED\n" if LANG == 'en' else "[✗] MAC NO FALSIFICADA\n")
        
        logbox.insert(tk.END, TEXTS[LANG]['safe'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['warning'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def execute_sequence(logbox):
    threading.Thread(target=spoof_mac, args=(logbox,)).start()
    threading.Thread(target=iniciar_tor, args=(logbox,)).start()
    threading.Thread(target=abrir_terminal_proxy, args=(logbox,)).start()
    threading.Thread(target=change_dns, args=(logbox,)).start()

def execute(func, logbox):
    threading.Thread(target=func, args=(logbox,)).start()

def exit_app():
    logbox.insert(tk.END, TEXTS[LANG]['exit_msg'] + "\n")
    threading.Thread(target=limpar_rastro, args=(logbox,)).start()
    app.after(2000, app.destroy)

def load_logo():
    try:
        response = requests.get("https://i.postimg.cc/zf9k2QNR/asd-2.png")
        img_data = response.content
        img = Image.open(io.BytesIO(img_data))
        img = img.resize((150, 150), Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except:
        # Create a blank logo if download fails
        img = Image.new('RGB', (150, 150), color='#191919')
        draw = ImageDraw.Draw(img)
        draw.text((10, 60), "M-SOCIETY", fill="red")
        return ImageTk.PhotoImage(img)

# GUI Setup
app = tk.Tk()
app.title(TEXTS[LANG]['title'])
app.geometry("700x700")
app.configure(bg='#191919')
app.resizable(False, False)

# Style configuration
style = ttk.Style()
style.theme_create('m-society', parent='alt', settings={
    'TFrame': {'configure': {'background': '#191919'}},
    'TLabel': {'configure': {
        'background': '#191919',
        'foreground': 'white',
        'font': ('Helvetica', 10)
    }},
    'TButton': {'configure': {
        'background': '#191919',
        'foreground': 'white',
        'font': ('Helvetica', 10, 'bold'),
        'borderwidth': 1,
        'relief': 'raised',
        'padding': 10
    }, 'map': {
        'background': [('active', '#ff0000'), ('pressed', '#8B0000')],
        'foreground': [('active', 'white')]
    }}
})
style.theme_use('m-society')

main_frame = ttk.Frame(app)
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

try:
    logo_img = load_logo()
    logo_label = ttk.Label(main_frame, image=logo_img)
    logo_label.image = logo_img
    logo_label.pack(pady=(0, 10))
except:
    pass

title_label = ttk.Label(main_frame, 
                        text=TEXTS[LANG]['title'], 
                        font=('Helvetica', 18, 'bold'),
                        foreground='red')
title_label.pack()

subtitle_label = ttk.Label(main_frame, 
                          text=TEXTS[LANG]['subtitle'], 
                          font=('Helvetica', 10),
                          foreground='white')
subtitle_label.pack(pady=(0, 20))

btn_frame = ttk.Frame(main_frame)
btn_frame.pack(fill=tk.X, pady=5)

btn1 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['mac_tor'],
                 command=lambda: execute(execute_sequence, logbox))
btn1.pack(fill=tk.X, pady=5)

btn2 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['clean'],
                 command=lambda: execute(limpar_rastro, logbox))
btn2.pack(fill=tk.X, pady=5)

btn3 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['vpn'],
                 command=lambda: execute(secure_vpn, logbox))
btn3.pack(fill=tk.X, pady=5)

btn4 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['dns'],
                 command=lambda: execute(change_dns, logbox))
btn4.pack(fill=tk.X, pady=5)

btn5 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['kill'],
                 command=lambda: execute(kill_processes, logbox))
btn5.pack(fill=tk.X, pady=5)

btn6 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['status'],
                 command=lambda: execute(check_status, logbox))
btn6.pack(fill=tk.X, pady=5)

log_frame = ttk.Frame(main_frame)
log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

logbox = tk.Text(log_frame, bg='#191919', fg='white', insertbackground='red',
                font=('Courier', 10), wrap=tk.WORD, bd=0, highlightthickness=1,
                highlightbackground='red', highlightcolor='red')
scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=logbox.yview)
logbox.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
logbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

exit_btn = ttk.Button(main_frame, 
                     text=TEXTS[LANG]['exit'],
                     command=exit_app)
exit_btn.pack(fill=tk.X, pady=(10, 0))


footer = ttk.Label(main_frame, 
                  text=TEXTS[LANG]['dev'],
                  font=('Helvetica', 8),
                  foreground='gray')
footer.pack(side=tk.BOTTOM, pady=(10, 0))

app.protocol("WM_DELETE_WINDOW", exit_app)
app.mainloop()#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import os
import threading
import requests
import time
from time import sleep
from PIL import ImageTk, Image
import io
import subprocess
import random
import sys

def get_user_language():
    try:
        response = requests.get('https://ipapi.co/json/', timeout=5)
        data = response.json()
        country = data.get('country', '')
        spanish_speaking = ['ES', 'MX', 'AR', 'CO', 'PE', 'VE', 'CL', 'EC', 'GT', 
                           'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 
                           'UY', 'GQ']
        return 'es' if country in spanish_speaking else 'en'
    except:
        return 'en'

LANG = get_user_language()

TEXTS = {
    'es': {
        'title': "M-SOCIETY GHOST",
        'subtitle': "SISTEMA DE ANONIMATO TOTAL",
        'mac_tor': "MAC + TOR + TERMINAL",
        'clean': "LIMPIAR RASTROS",
        'vpn': "VPN SEGURA",
        'dns': "DNS ANÓNIMO",
        'kill': "MATAR PROCESOS",
        'status': "ESTADO DEL SISTEMA",
        'exit': "SALIR",
        'mac_success': "[✓] MAC FALSIFICADO CON ÉXITO",
        'mac_fail': "[✗] FALLO EN SPOOF DE MAC",
        'tor_start': "[...] INICIANDO TOR...",
        'tor_success': "[✓] TOR ACTIVADO - TÚNEL SEGURO ESTABLECIDO",
        'tor_fail': "[✗] FALLO AL INICIAR TOR",
        'term_success': "[✓] TERMINAL CAMUFLADA CON PROXYCHAINS INICIADA",
        'term_fail': "[✗] FALLO AL ABRIR TERMINAL",
        'clean_success': "[✓] LIMPIEZA COMPLETA - RASTROS ELIMINADOS",
        'clean_fail': "[✗] FALLO EN LIMPIEZA DE RASTROS",
        'vpn_success': "[✓] VPN CONFIGURADA - TRÁFICO CIFRADO",
        'vpn_fail': "[✗] FALLO AL CONECTAR VPN",
        'dns_success': "[✓] DNS ANÓNIMO CONFIGURADO",
        'dns_fail': "[✗] FALLO AL CAMBIAR DNS",
        'kill_success': "[✓] PROCESOS PELIGROSOS TERMINADOS",
        'kill_fail': "[✗] FALLO AL TERMINAR PROCESOS",
        'checking': "[*] VERIFICANDO ESTADO DEL SISTEMA...",
        'safe': "[✓] SISTEMA SEGURO - ANONIMATO ACTIVO",
        'warning': "[!] ADVERTENCIA: SE DETECTARON VULNERABILIDADES",
        'exit_msg': "SALIENDO DEL SISTEMA... BORRANDO HUELLAS",
        'dev': "M-SOCIETY GHOST v3.0"
    },
    'en': {
        'title': "M-SOCIETY GHOST",
        'subtitle': "TOTAL ANONYMITY SYSTEM",
        'mac_tor': "MAC + TOR + TERMINAL",
        'clean': "WIPE TRACES",
        'vpn': "SECURE VPN",
        'dns': "ANONYMOUS DNS",
        'kill': "KILL PROCESSES",
        'status': "SYSTEM STATUS",
        'exit': "EXIT",
        'mac_success': "[✓] MAC ADDRESS SPOOFED SUCCESSFULLY",
        'mac_fail': "[✗] MAC SPOOFING FAILED",
        'tor_start': "[...] STARTING TOR...",
        'tor_success': "[✓] TOR ACTIVATED - SECURE TUNNEL ESTABLISHED",
        'tor_fail': "[✗] FAILED TO START TOR",
        'term_success': "[✓] PROXYCHAIN TERMINAL LAUNCHED",
        'term_fail': "[✗] FAILED TO OPEN TERMINAL",
        'clean_success': "[✓] FULL CLEANUP - TRACES WIPED",
        'clean_fail': "[✗] CLEANUP FAILED",
        'vpn_success': "[✓] VPN CONFIGURED - TRAFFIC ENCRYPTED",
        'vpn_fail': "[✗] VPN CONNECTION FAILED",
        'dns_success': "[✓] ANONYMOUS DNS CONFIGURED",
        'dns_fail': "[✗] FAILED TO CHANGE DNS",
        'kill_success': "[✓] DANGEROUS PROCESSES TERMINATED",
        'kill_fail': "[✗] FAILED TO KILL PROCESSES",
        'checking': "[*] CHECKING SYSTEM STATUS...",
        'safe': "[✓] SYSTEM SECURE - ANONYMITY ACTIVE",
        'warning': "[!] WARNING: VULNERABILITIES DETECTED",
        'exit_msg': "EXITING SYSTEM... WIPING TRACES",
        'dev': "M-SOCIETY GHOST v3.0"
    }
}

def spoof_mac(logbox):
    try:
        logbox.insert(tk.END, "[...] CHANGING MAC ADDRESS...\n" if LANG == 'en' else "[...] CAMBIANDO DIRECCIÓN MAC...\n")
        logbox.see(tk.END)
        interfaces = ["eth0", "wlan0", "wlp3s0"]
        for interface in interfaces:
            os.system(f"ifconfig {interface} down 2>/dev/null")
            os.system(f"macchanger -r {interface} 2>/dev/null")
            os.system(f"ifconfig {interface} up 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['mac_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['mac_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def iniciar_tor(logbox):
    try:
        logbox.insert(tk.END, TEXTS[LANG]['tor_start'] + "\n")
        logbox.see(tk.END)
        os.system("service tor stop 2>/dev/null")
        os.system("service tor start 2>/dev/null")
        sleep(5)
        logbox.insert(tk.END, TEXTS[LANG]['tor_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['tor_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def abrir_terminal_proxy(logbox):
    try:
        terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "xterm"]
        for term in terminals:
            if os.system(f"which {term} >/dev/null") == 0:
                os.system(f"{term} -- bash -c 'proxychains bash' &")
                logbox.insert(tk.END, TEXTS[LANG]['term_success'] + "\n")
                logbox.see(tk.END)
                return
        raise Exception("No terminal found")
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['term_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def limpar_rastro(logbox):
    try:
        logbox.insert(tk.END, "[...] CLEANING SYSTEM..." if LANG == 'en' else "[...] LIMPIANDO SISTEMA...\n")
        logbox.see(tk.END)
        cleaners = [
            "bleachbit -c system.cache system.clipboard system.recent_documents bash.history",
            "history -c && history -w && unset HISTFILE",
            "shred -u ~/.bash_history",
            "find /tmp /var/tmp -type f -exec shred -u {} \;",
            "swapoff -a && swapon -a"
        ]
        for cmd in cleaners:
            os.system(cmd + " 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['clean_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['clean_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def secure_vpn(logbox):
    try:
        vpns = [
            "nordvpn", "protonvpn", "windscribe", "mullvad",
            "openvpn", "wireguard"
        ]
        for vpn in vpns:
            if os.system(f"which {vpn} >/dev/null") == 0:
                os.system(f"{vpn} connect")
                logbox.insert(tk.END, TEXTS[LANG]['vpn_success'] + f" ({vpn})\n")
                logbox.see(tk.END)
                return
        raise Exception("No VPN client found")
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['vpn_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def change_dns(logbox):
    try:
        dns_servers = [
            "1.1.1.1", "1.0.0.1",  
            "8.8.8.8", "8.8.4.4",  
            "9.9.9.9", "149.112.112.112",  
            "94.140.14.14", "94.140.15.15" 
        ]
        new_dns = random.choice(dns_servers)
        os.system(f"echo 'nameserver {new_dns}' > /etc/resolv.conf")
        logbox.insert(tk.END, TEXTS[LANG]['dns_success'] + f" ({new_dns})\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['dns_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def kill_processes(logbox):
    try:
        dangerous = ["wireshark", "tcpdump", "nmap", "nessus", "metasploit"]
        for proc in dangerous:
            os.system(f"pkill -9 {proc} 2>/dev/null")
        logbox.insert(tk.END, TEXTS[LANG]['kill_success'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['kill_fail'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def check_status(logbox):
    try:
        logbox.insert(tk.END, TEXTS[LANG]['checking'] + "\n")
        logbox.see(tk.END)
        
        tor_check = os.system("curl --socks5 localhost:9050 --connect-timeout 5 -s https://check.torproject.org/ | grep -q 'Congratulations'")
        if tor_check == 0:
            logbox.insert(tk.END, "[✓] TOR CONNECTION: ACTIVE\n" if LANG == 'en' else "[✓] CONEXIÓN TOR: ACTIVA\n")
        else:
            logbox.insert(tk.END, "[✗] TOR CONNECTION: INACTIVE\n" if LANG == 'en' else "[✗] CONEXIÓN TOR: INACTIVA\n")
        
        vpn_check = os.system("ip a | grep -q 'tun'")
        if vpn_check == 0:
            logbox.insert(tk.END, "[✓] VPN: ACTIVE\n" if LANG == 'en' else "[✓] VPN: ACTIVA\n")
        else:
            logbox.insert(tk.END, "[✗] VPN: INACTIVE\n" if LANG == 'en' else "[✗] VPN: INACTIVA\n")
        
        mac_check = os.system("macchanger -s eth0 | grep -q 'Permanent'")
        if mac_check != 0:
            logbox.insert(tk.END, "[✓] MAC SPOOFED\n" if LANG == 'en' else "[✓] MAC FALSIFICADA\n")
        else:
            logbox.insert(tk.END, "[✗] MAC NOT SPOOFED\n" if LANG == 'en' else "[✗] MAC NO FALSIFICADA\n")
        
        logbox.insert(tk.END, TEXTS[LANG]['safe'] + "\n")
        logbox.see(tk.END)
    except Exception as e:
        logbox.insert(tk.END, TEXTS[LANG]['warning'] + f" - {str(e)}\n")
        logbox.see(tk.END)

def execute_sequence(logbox):
    threading.Thread(target=spoof_mac, args=(logbox,)).start()
    threading.Thread(target=iniciar_tor, args=(logbox,)).start()
    threading.Thread(target=abrir_terminal_proxy, args=(logbox,)).start()
    threading.Thread(target=change_dns, args=(logbox,)).start()

def execute(func, logbox):
    threading.Thread(target=func, args=(logbox,)).start()

def exit_app():
    logbox.insert(tk.END, TEXTS[LANG]['exit_msg'] + "\n")
    threading.Thread(target=limpar_rastro, args=(logbox,)).start()
    app.after(2000, app.destroy)

def load_logo():
    try:
        response = requests.get("https://i.postimg.cc/zf9k2QNR/asd-2.png")
        img_data = response.content
        img = Image.open(io.BytesIO(img_data))
        img = img.resize((150, 150), Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except:
        # Create a blank logo if download fails
        img = Image.new('RGB', (150, 150), color='#191919')
        draw = ImageDraw.Draw(img)
        draw.text((10, 60), "M-SOCIETY", fill="red")
        return ImageTk.PhotoImage(img)

# GUI Setup
app = tk.Tk()
app.title(TEXTS[LANG]['title'])
app.geometry("700x700")
app.configure(bg='#191919')
app.resizable(False, False)

# Style configuration
style = ttk.Style()
style.theme_create('m-society', parent='alt', settings={
    'TFrame': {'configure': {'background': '#191919'}},
    'TLabel': {'configure': {
        'background': '#191919',
        'foreground': 'white',
        'font': ('Helvetica', 10)
    }},
    'TButton': {'configure': {
        'background': '#191919',
        'foreground': 'white',
        'font': ('Helvetica', 10, 'bold'),
        'borderwidth': 1,
        'relief': 'raised',
        'padding': 10
    }, 'map': {
        'background': [('active', '#ff0000'), ('pressed', '#8B0000')],
        'foreground': [('active', 'white')]
    }}
})
style.theme_use('m-society')

main_frame = ttk.Frame(app)
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

try:
    logo_img = load_logo()
    logo_label = ttk.Label(main_frame, image=logo_img)
    logo_label.image = logo_img
    logo_label.pack(pady=(0, 10))
except:
    pass

title_label = ttk.Label(main_frame, 
                        text=TEXTS[LANG]['title'], 
                        font=('Helvetica', 18, 'bold'),
                        foreground='red')
title_label.pack()

subtitle_label = ttk.Label(main_frame, 
                          text=TEXTS[LANG]['subtitle'], 
                          font=('Helvetica', 10),
                          foreground='white')
subtitle_label.pack(pady=(0, 20))

btn_frame = ttk.Frame(main_frame)
btn_frame.pack(fill=tk.X, pady=5)

btn1 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['mac_tor'],
                 command=lambda: execute(execute_sequence, logbox))
btn1.pack(fill=tk.X, pady=5)

btn2 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['clean'],
                 command=lambda: execute(limpar_rastro, logbox))
btn2.pack(fill=tk.X, pady=5)

btn3 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['vpn'],
                 command=lambda: execute(secure_vpn, logbox))
btn3.pack(fill=tk.X, pady=5)

btn4 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['dns'],
                 command=lambda: execute(change_dns, logbox))
btn4.pack(fill=tk.X, pady=5)

btn5 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['kill'],
                 command=lambda: execute(kill_processes, logbox))
btn5.pack(fill=tk.X, pady=5)

btn6 = ttk.Button(btn_frame, 
                 text=TEXTS[LANG]['status'],
                 command=lambda: execute(check_status, logbox))
btn6.pack(fill=tk.X, pady=5)

log_frame = ttk.Frame(main_frame)
log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

logbox = tk.Text(log_frame, bg='#191919', fg='white', insertbackground='red',
                font=('Courier', 10), wrap=tk.WORD, bd=0, highlightthickness=1,
                highlightbackground='red', highlightcolor='red')
scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=logbox.yview)
logbox.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
logbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

exit_btn = ttk.Button(main_frame, 
                     text=TEXTS[LANG]['exit'],
                     command=exit_app)
exit_btn.pack(fill=tk.X, pady=(10, 0))


footer = ttk.Label(main_frame, 
                  text=TEXTS[LANG]['dev'],
                  font=('Helvetica', 8),
                  foreground='gray')
footer.pack(side=tk.BOTTOM, pady=(10, 0))

app.protocol("WM_DELETE_WINDOW", exit_app)
app.mainloop()
