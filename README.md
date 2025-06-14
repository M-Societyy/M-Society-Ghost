# 🛡️ M-SOCIETY GHOST v3.0

Sistema de anonimato total con interfaz gráfica para GNU/Linux.

**M-SOCIETY GHOST** es una herramienta avanzada diseñada para aumentar la privacidad y el anonimato en entornos Linux. A través de una interfaz gráfica construida con `tkinter`, automatiza acciones de spoofing de MAC, activación de TOR, uso de DNS anónimos, terminal camuflada, procesos peligrosos, uso de VPNs y limpieza forense del sistema.

---

## 📦 Características

- **Cambio aleatorio de dirección MAC** (`macchanger`)
- **Activación de TOR** y verificación del túnel seguro
- **Apertura de terminal con `proxychains` para navegación anónima**
- **Cambio de DNS por servidores públicos y anónimos**
- **Intento de conexión a VPNs populares automáticamente**
- **Eliminación de procesos considerados "peligrosos"**
- **Limpieza forense de rastros (bash history, cache, clipboard, etc.)**
- **Chequeo de estado del anonimato del sistema**
- **Soporte multiidioma automático (español o inglés) detectado por IP**
- **GUI interactiva con botones funcionales y salida de logs en tiempo real**

---

## 🚨 Requisitos

El script **requiere privilegios de root** (`sudo`) para funcionar correctamente.

### Dependencias del sistema:
Instala los siguientes paquetes si no los tienes:

```bash
sudo apt install macchanger tor proxychains bleachbit curl python3-pil python3-requests
````

Si planeas usar VPN:

* ProtonVPN CLI
* NordVPN CLI
* OpenVPN
* WireGuard
* Windscribe
* Mullvad

Instala al menos uno.

---

## 🖥️ Entornos compatibles

* **Distribuciones Linux basadas en Debian/Ubuntu**
* Escritorios: GNOME, KDE, XFCE, X11 (`xterm`, `gnome-terminal`, etc.)
* No compatible con **Wayland** por defecto (requiere ajustes adicionales)

---

## ⚙️ ¿Qué hace exactamente?

### 🔧 Cambiar MAC

* Spoofea las interfaces `eth0`, `wlan0`, `wlp3s0` (si existen)
* Usa `macchanger` de forma silenciosa (`2>/dev/null`)

### 🧅 Activar TOR

* Detiene y vuelve a iniciar el servicio `tor`
* Espera 5 segundos antes de continuar
* Verifica si se ha conectado correctamente usando `check.torproject.org`

### 📦 Proxychains

* Abre una terminal con `proxychains bash` para conexión encadenada

### 🌐 Cambiar DNS

* Reemplaza el contenido de `/etc/resolv.conf` con servidores aleatorios como:

  * `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, etc.

### 🧽 Limpiar rastros

Ejecuta una limpieza **forense ligera** que incluye:

* Cache del sistema (`bleachbit`)
* Clipboard
* Documentos recientes
* Historial de Bash (`~/.bash_history`, `history -c`)
* Archivos temporales (`/tmp`, `/var/tmp`)
* Reinicio de `swap`

### 🔒 VPN

* Detecta e intenta conectar con **el primer cliente VPN disponible** instalado
* Muestra en logs cuál fue usado (si se logró)

### 🔪 Kill Processes

* Mata procesos como: `wireshark`, `tcpdump`, `nmap`, `nessus`, `metasploit`
* Usa `pkill -9` para forzarlos

### ✅ Chequeo del sistema

Verifica:

* Si TOR está funcionando correctamente
* Si hay interfaces `tun` activas (VPN)
* Si la MAC ha sido falsificada (basado en salida de `macchanger`)

---

## ⚠️ Advertencias y Limitaciones

### ❗ No oculta todo:

* No cifra el tráfico completo del sistema si no se logra activar VPN
* No configura un entorno sandbox ni desactiva WebRTC ni JS (se requiere navegador anónimo aparte)
* **No usa Tails, Whonix ni Qubes** (entornos diseñados para anonimato real)
* No persiste los cambios después del reinicio (MAC, DNS, etc.)
* No borra registros del sistema (`/var/log/*`)
* **No verifica si las VPNs realmente se conectaron exitosamente**
* Requiere permisos de escritura sobre `/etc/resolv.conf` (root)
* **Puede romper conectividad si se cambia mal la MAC o DNS**
* No cifra la partición SWAP, solo la reinicia

### 💥 Posibles errores:

* Fallo al iniciar `tor` si no está correctamente configurado
* Fallo al abrir terminal si ninguna está instalada (`gnome-terminal`, `konsole`, `xterm`, etc.)
* Fallo al encontrar una VPN disponible
* Problemas de red si el `proxychains` está mal configurado
* No encuentra interfaces de red si tienen nombres diferentes a `eth0` o `wlan0`

---

## 🚀 Ejecución

Recomendado: usar con permisos de superusuario.

```bash
sudo python3 m_society_ghost.py
```

---

## 📸 Captura de pantalla

![M-SOCIETY GHOST Screenshot](https://i.postimg.cc/zf9k2QNR/asd-2.png)

---

## 👨‍💻 Autor

**M-SOCIETY TEAM**
Versión: 1.0

---

## 🧩 To-Do / Mejoras futuras

* Mejor detección de VPN conectada
* Añadir verificación de logs de `tor`
* Opcional: modo CLI (sin GUI)
* Integración con entornos como Tails/Whonix
* Protección contra WebRTC y fingerprinting

---
