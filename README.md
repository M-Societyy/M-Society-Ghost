## M-Society Ghost
---

## 🔥 Características
- Spoofing de dirección MAC automático
- Tunnelización con Tor integrada
- Terminal protegida con Proxychains
- Limpieza forense avanzada
- Cambio automático de DNS
- Detección y eliminación de procesos riesgosos
- Interfaz elegante (negro/rojo/blanco)
- Detección automática de idioma

## ⚠️ Advertencia Legal
```diff
- Esta herramienta debe usarse ÚNICAMENTE para:
+ Pruebas de seguridad autorizadas
+ Investigación forense
+ Protección de privacidad personal

- NUNCA para:
- Actividades ilegales
- Vulneración de sistemas sin autorización
- Fraude o robo de información
```

## 🛠 Requisitos
```bash
# Sistemas compatibles:
- Kali Linux / Parrot OS (recomendado)
- Ubuntu/Debian (requiere configuración adicional)
- No soportado en Windows/MacOS

# Dependencias esenciales:
sudo apt install -y tor macchanger proxychains bleachbit python3-pip
```

## 🚀 Instalación
```bash
# 1. Clonar repositorio
git clone https://github.com/tuusuario/M-Society-Ghost.git
cd M-Society-Ghost

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar (como root)
sudo python3 src/m_society_ghost.py
```

## 🖥 Uso Básico
1. Ejecuta el script como root
2. Presiona "MAC + TOR + TERMINAL" para:
   - Cambiar tu dirección MAC
   - Activar Tor
   - Abrir terminal anónima
3. Usa "LIMPIAR RASTROS" antes de cerrar

## 🛡️ Protocolo de Seguridad Recomendado
1. Conéctate a una red pública/WiFi abierto
2. Ejecuta M-Society Ghost
3. Usa la terminal generada para todas tus operaciones
4. Limpia rastros antes de cerrar
5. Reinicia el dispositivo después de usar

## 📌 Limitaciones Conocidas
```diff
! No proporciona anonimato 100% garantizado
! Puede ser detectado por sistemas avanzados de DPI
! Requiere configuración manual en algunas distribuciones
```
---

<p align="center">
  «El conocimiento debe ser libre» - M-Society
</p>
```

# 📝 requirements.txt
```
requests==2.28.1
Pillow==9.3.0
```
