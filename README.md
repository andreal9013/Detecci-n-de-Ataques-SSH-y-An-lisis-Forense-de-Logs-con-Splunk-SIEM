# Detección de Ataques SSH y Análisis Forense de Logs con Splunk SIEM

## 1. Resumen Ejecutivo
Este proyecto documenta la ingesta, análisis forense y correlación de eventos de seguridad sobre registros de autenticación Linux (`auth.log`) utilizando la plataforma **Splunk Enterprise**. A través de consultas en **SPL (Search Processing Language)** y expresiones regulares (`rex`), se identificó un ataque coordinado de fuerza bruta SSH proveniente de la dirección IP `192.168.1.150`, el cual culminó en el compromiso exitoso de la cuenta de usuario local `andres`.

---

## 2. Entorno y Herramientas
* **Plataforma SIEM:** Splunk Enterprise v9.x (Instalación Local)
* **Lenguaje de Consulta:** Search Processing Language (SPL)
* **Fuente de Datos (*Datasource*):** `auth.log` (Syslog / Linux SSHD)
* **Índice de Ingesta:** `main` / `cybersecurity`

---

## 3. Metodología e Investigación con SPL

### Fase 1: Identificación General de Eventos de Autenticación
Inspección inicial de los registros para verificar la ingesta correcta de los eventos y la estructura de los datos del servicio `sshd`.

```splunk
source="auth.log"
Fase 2: Aislamiento e Inspección de Intentos Fallidos
Fragmento de código
source="auth.log" "Failed password"
Fase 3: Extracción de Campos y Correlación de Fuerza Bruta
Uso de expresiones regulares para extraer dinámicamente la IP de origen (src_ip) y el usuario objetivo (user), agrupando los intentos para determinar el vector de ataque principal.
Fragmento de código
source="auth.log" "Failed password"
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as "Intentos Fallidos" by src_ip, user
| sort - "Intentos Fallidos"
Fase 4: Confirmación de Compromiso de Cuenta
Filtrado de eventos de inicio de sesión exitosos (Accepted password) para correlacionar si la dirección IP atacante logró adivinar credenciales válidas tras la ráfaga de intentos fallidos.
Fragmento de código
source="auth.log" "Accepted password"
4. Matriz de Hallazgos y Análisis del Incidente
IP Origen,Tipo de Evento,Usuarios Evaluados,Total Eventos,Indicador de Compromiso (IoC)
192.168.1.150,Failed password,"root (raíz), admin (administración), andres, user1, test (prueba)",9,Ataque Activo de Fuerza Bruta: Escaneo dicotómico de usuarios comunes.
192.168.1.150,Accepted password,andres,1,Compromiso Exitoso: Login correcto a las 10:01:32 tras múltiples fallos.
203.0.113.45,Failed password,root (raíz),2,Intento Externo Reincidente: Intentos aislados sobre la cuenta privilegiada.
10.0.0.15,Accepted password,sysadmin,1,Tráfico Legítimo: Acceso de administración desde la red interna a las 10:05:12.
5. Visualización: Dashboard de Monitoreo
Para permitir la detección continua en el SOC, se construyó un Dashboard interactivo en Splunk que visualiza en tiempo real los principales vectores de ataque por dirección IP y cuenta de usuario afectada.
+-----------------------------------------------------------------------------------+
|                        Monitoreo de fuerza bruta SSH                              |
|   Principales intentos de inicio de sesión fallidos por IP y usuario              |
+-----------------------------------------------------------------------------------+
| src_ip          | usuario        | Intentos Fallidos                              |
+-----------------+----------------+------------------------------------------------+
| 192.168.1.150   | raíz           | 3                                              |
| 192.168.1.150   | administración | 2                                              |
| 192.168.1.150   | andres         | 2                                              |
| 203.0.113.45    | raíz           | 2                                              |
| 192.168.1.150   | prueba         | 1                                              |
| 192.168.1.150   | usuario1       | 1                                              |
+-----------------+----------------+------------------------------------------------+
6. Plan de Respuesta a Incidentes y Mitigación
Contención Inmediata:

Bloquear la dirección IP 192.168.1.150 a nivel de firewall de red y tabla local (iptables / nftables).

Forzar el cierre de la sesión activa del usuario andres y solicitar el restablecimiento inmediato de su contraseña.

Hardening de SSH:

Deshabilitar la autenticación por contraseña e implementar exclusivamente claves públicas/privadas SSH (PubkeyAuthentication yes).

Deshabilitar el acceso directo al usuario privilegiado cambiando la directiva a PermitRootLogin no.

Automatización de Defensas:

Instalar y configurar herramientas como Fail2ban para bloquear automáticamente direcciones IP que superen los 3 intentos fallidos consecutivos en un lapso de 5 minutos.

Regla de Alerta en SIEM (SPL Rule):

Configurar una alerta programada en Splunk que notifique al equipo SOC cuando un mismo src_ip registre más de 5 intentos fallidos en un intervalo de 1 minuto.

Filtrado directo de los eventos donde el servidor rechazó las credenciales ingresadas, confirmando un volumen anómalo de autenticaciones fallidas.
