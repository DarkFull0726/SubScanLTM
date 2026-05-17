#!/usr/bin/env python3
# ════════════════════════════════════════════════
#   SubScanLTM — Escaner de subdominios y bug hosts
#   Creado por @DarkZFull
#   Canal: https://t.me/LTMCHANNEL
# ════════════════════════════════════════════════

import os, sys, subprocess

DEPS = ["requests", "dnspython", "rich", "colorama"]

def auto_install():
    missing = []
    for dep in DEPS:
        try: __import__(dep.replace("-","_"))
        except ImportError: missing.append(dep)
    if missing:
        print(f"\n  Instalando: {', '.join(missing)}...")
        for dep in missing:
            subprocess.run([sys.executable,"-m","pip","install",dep,"-q"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("  Listo\n")

auto_install()

import socket, ssl, re, time, threading
import concurrent.futures
from datetime import datetime

import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
import colorama
colorama.init()

requests.packages.urllib3.disable_warnings()
console = Console()

VERSION  = "1.4.0"
AUTHOR   = "@DarkZFull"
CANAL    = "https://t.me/LTMCHANNEL"
TIMEOUT  = 8
THREADS  = 50

# Carpeta de guardado
SAVE_DIR = "/sdcard/Download/SubScanLTM"

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,465,587,993,995,
                1080,3128,3306,3389,5432,6379,8080,8081,8443,
                8888,9090,9443,27017,1194,1723,8000,8008]

PORT_NAMES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP-TLS",
    993:"IMAPS",995:"POP3S",1080:"SOCKS5",3128:"Proxy",3306:"MySQL",
    3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",
    8081:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",9090:"HTTP-Alt",
    9443:"HTTPS-Alt",27017:"MongoDB",1194:"OpenVPN",1723:"PPTP",
    8000:"HTTP-Dev",8008:"HTTP-Alt",
}

CDN_SIGNATURES = {
    "Cloudflare":       {"headers":["cf-ray","cf-cache-status"],         "server":["cloudflare"],  "cname":["cloudflare.com","cloudflare.net"]},
    "Cloudfront (AWS)": {"headers":["x-amz-cf-id","x-amz-cf-pop"],      "server":["cloudfront"],  "cname":["cloudfront.net"]},
    "Akamai":           {"headers":["x-akamai-request-id","akamai-grn"], "server":["akamai"],      "cname":["akamai.net","akamaiedge.net"]},
    "Fastly":           {"headers":["x-fastly-request-id"],              "server":["fastly"],      "cname":["fastly.net"]},
    "Azure CDN":        {"headers":["x-azure-ref"],                      "server":["ecd"],         "cname":["azureedge.net","azurefd.net"]},
    "Google CDN":       {"headers":["x-goog-generation"],                "server":["gws"],         "cname":["googleapis.com"]},
    "Incapsula":        {"headers":["x-iinfo"],                          "server":["incapsula"],   "cname":["incapdns.net"]},
    "Sucuri":           {"headers":["x-sucuri-id"],                      "server":["sucuri"],      "cname":["sucuri.net"]},
    "BunnyCDN":         {"headers":["bunnycdn-cache"],                   "server":["bunny"],       "cname":["b-cdn.net"]},
}

# ════════════════════════════════════════════════
#   PAYLOADS HTTP CUSTOM
# ════════════════════════════════════════════════
def generar_payload(host, cdn, puerto):
    CF  = "Cloudflare" in cdn
    CFR = "Cloudfront" in cdn
    CDN = any(x in cdn for x in ["Akamai","Fastly","Azure","Google","BunnyCDN"])
    S443 = puerto in [443, 8443]

    CRLF = "[crlf]"

    if CF or CFR:
        nombre = "Cloudflare" if CF else "Cloudfront (AWS)"
        tipo   = f"{nombre} WebSocket"
        payload = (
            f"GET / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Connection: Upgrade{CRLF}"
            f"User-Agent: [ua]{CRLF}"
            f"Upgrade: websocket{CRLF}{CRLF}"
        )
        front = host
        nota  = f"Pon este dominio en el campo Host/SNI de HTTP Custom"

    elif CDN and S443:
        tipo = "CDN Front HTTPS"
        payload = (
            f"GET / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Connection: Upgrade{CRLF}"
            f"User-Agent: [ua]{CRLF}"
            f"Upgrade: websocket{CRLF}{CRLF}"
        )
        front = host
        nota  = "Domain fronting via CDN HTTPS"

    elif CDN and not S443:
        tipo = "CDN Front HTTP"
        payload = (
            f"GET / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Connection: Keep-Alive{CRLF}"
            f"User-Agent: [ua]{CRLF}{CRLF}"
        )
        front = host
        nota  = "Domain fronting HTTP"

    elif S443:
        tipo = "Direct HTTPS"
        payload = (
            f"CONNECT [host_vps]:[puerto] HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Connection: Keep-Alive{CRLF}"
            f"User-Agent: [ua]{CRLF}{CRLF}"
        )
        front = "—"
        nota  = "Conexion directa HTTPS sin CDN"

    else:
        tipo = "Direct HTTP"
        payload = (
            f"GET / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Connection: Keep-Alive{CRLF}"
            f"User-Agent: [ua]{CRLF}{CRLF}"
        )
        front = "—"
        nota  = "Conexion directa HTTP sin CDN"

    return tipo, payload, front, nota


# ════════════════════════════════════════════════
#   UTILIDADES
# ════════════════════════════════════════════════
def cls(): os.system("clear")

def clean_domain(raw):
    raw = raw.strip().lower()
    raw = re.sub(r'^https?://', '', raw)
    return raw.split('/')[0]

def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def ask(prompt):
    return console.input(f"  [bold yellow]  >[/bold yellow] {prompt}: ").strip()

def row(label, value, color="bright_white"):
    console.print(f"  [dim white]  {label:<24}[/dim white][{color}]{value}[/{color}]")

def titulo(texto):
    console.print(f"\n  [bold yellow]◆[/bold yellow] [bold bright_white]{texto}[/bold bright_white]")
    console.print(f"  [yellow]{'─'*52}[/yellow]")

def separador():
    console.print(f"  [dim yellow]{'─'*52}[/dim yellow]")

def http_get(url):
    try:
        return requests.get(url, timeout=TIMEOUT, verify=False,
                            allow_redirects=True,
                            headers={"User-Agent":"Mozilla/5.0 SubScanLTM"})
    except: return None

def ip_es_cloudfront(ip):
    """IPs en rangos conocidos de Cloudfront"""
    if not ip: return False
    # Rangos comunes de AWS Cloudfront
    prefijos_cf = [
        "13.32.","13.35.","13.224.","13.225.","13.226.","13.227.","13.228.",
        "13.249.","13.249.","18.64.","18.65.","18.66.","18.67.","18.68.",
        "52.84.","52.85.","52.222.","52.46.","64.252.","65.8.","65.9.",
        "70.132.","99.84.","108.156.","108.157.","108.158.","108.159.",
        "143.204.","204.246.","205.251.","216.137.",
    ]
    return any(ip.startswith(p) for p in prefijos_cf)

def ip_es_cloudflare(ip):
    """IPs en rangos conocidos de Cloudflare"""
    if not ip: return False
    prefijos = [
        "103.21.","103.22.","103.31.","104.16.","104.17.","104.18.","104.19.","104.20.","104.21.",
        "108.162.","131.0.72.","141.101.","162.158.","172.64.","172.65.","172.66.","172.67.",
        "173.245.","188.114.","190.93.","197.234.","198.41.",
    ]
    return any(ip.startswith(p) for p in prefijos)

def detect_cdn(domain, response=None, cnames=None, ip=None):
    found = []
    hdrs, server = {}, ""
    if response:
        hdrs = {k.lower():v.lower() for k,v in response.headers.items()}
        server = hdrs.get("server","")
    for cdn, sigs in CDN_SIGNATURES.items():
        hit  = any(h in hdrs for h in sigs["headers"])
        hit  = hit or any(s in server for s in sigs["server"])
        if cnames:
            hit = hit or any(p in cn for cn in cnames for p in sigs["cname"])
        if hit: found.append(cdn)
    # Detección adicional por IP si no se detectó nada por headers/cname
    if not found and ip:
        if ip_es_cloudfront(ip):
            found.append("Cloudfront (AWS)")
        elif ip_es_cloudflare(ip):
            found.append("Cloudflare")
    return found if found else ["Ninguno"]

def guardar_archivo(nombre, contenido):
    """Guarda en /sdcard/Download/SubScanLTM/ y muestra ruta"""
    try:
        os.makedirs(SAVE_DIR, exist_ok=True)
        ruta = os.path.join(SAVE_DIR, nombre)
        with open(ruta, "w") as f:
            f.write(contenido)
        console.print(f"  [bright_green]✔ Guardado en:[/bright_green] [white]{ruta}[/white]")
        return ruta
    except:
        # Fallback a home si no hay acceso a sdcard
        ruta = os.path.expanduser(f"~/{nombre}")
        with open(ruta, "w") as f:
            f.write(contenido)
        console.print(f"  [yellow]✔ Guardado en (home):[/yellow] [white]{ruta}[/white]")
        return ruta


# ════════════════════════════════════════════════
#   BANNER
# ════════════════════════════════════════════════
def banner():
    cls()
    console.print()
    console.print("  [bold bright_yellow] ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄[/bold bright_yellow]")
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][bold bright_white]  SubScan[/bold bright_white][bold bright_green]LTM[/bold bright_green][bold bright_yellow]                           ██[/bold bright_yellow]")
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Escaner de subdominios y bug hosts  [/dim white][bold bright_yellow]██[/bold bright_yellow]")
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Creado por [/dim white][bold bright_green]{:<10}[/bold bright_green][dim white]  v{:<14}[/dim white][bold bright_yellow]██[/bold bright_yellow]".format(AUTHOR, VERSION))
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Canal: [/dim white][bold bright_cyan]{:<30}[/bold bright_cyan][bold bright_yellow]██[/bold bright_yellow]".format(CANAL))
    console.print("  [bold bright_yellow] ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/bold bright_yellow]")
    console.print()

def menu():
    banner()
    console.print("  [bold bright_green]  MENU PRINCIPAL[/bold bright_green]")
    console.print("  [dim yellow]  ══════════════════════════════════════[/dim yellow]")
    console.print()
    for num, name, color, desc in [
        ("1","HOST SCANNER",  "bright_green",   "Detecta bug hosts + payload HTTP Custom"),
        ("2","SUBFINDER",     "bright_cyan",    "Subdominios + deteccion de CDN"),
        ("3","IP LOOKUP",     "bright_magenta", "Reverse IP + geolocalizacion"),
        ("4","PORT SCANNER",  "bright_yellow",  "Escanea puertos abiertos"),
        ("5","DNS RECORDS",   "bright_blue",    "Registros A, MX, NS, TXT..."),
        ("6","HOST INFO",     "bright_white",   "CDN, servidor, SSL, headers"),
        ("7","FULL SCAN",     "bold bright_red","Todo en uno sobre un dominio"),
        ("0","SALIR",         "dim red",        ""),
    ]:
        if num == "0":
            console.print(f"  [dim]  [{num}][/dim]  [{color}]{name}[/{color}]")
        else:
            console.print(f"  [bold bright_yellow]  [{num}][/bold bright_yellow]  [{color}]{name:<18}[/{color}][dim white]{desc}[/dim white]")
    console.print()
    console.print("  [dim yellow]  ══════════════════════════════════════[/dim yellow]")
    return console.input(f"\n  [bold bright_yellow]  >[/bold bright_yellow] Opcion: ").strip()


# ════════════════════════════════════════════════
#   1. HOST SCANNER
# ════════════════════════════════════════════════
def host_scanner():
    banner()
    titulo("HOST SCANNER  —  Detector de Bug Hosts")
    modo = ask("Dominio unico o archivo? (d/f)")
    targets = []
    if modo.lower() == "f":
        path = ask("Ruta del archivo")
        try:
            with open(path) as f:
                targets = [clean_domain(l) for l in f if l.strip()]
        except:
            console.print("  [red]✘ No se pudo abrir el archivo[/red]")
            input("\n  Enter..."); return
    else:
        targets = [clean_domain(ask("Dominio o IP"))]

    results_ok = []
    lock = threading.Lock()

    table = Table(box=box.ROUNDED, header_style="bold bright_yellow",
                  border_style="yellow", show_lines=False)
    table.add_column("Host",     style="bright_white", no_wrap=True)
    table.add_column("IP",       style="dim white")
    table.add_column("Puerto",   justify="center", style="cyan")
    table.add_column("CDN",      style="bright_magenta", max_width=14)
    table.add_column("Tipo",     style="bright_cyan",    max_width=18)
    table.add_column("Front",    style="bright_yellow",  max_width=20)
    table.add_column("Estado",   justify="center")

    def scan(domain):
        ip = resolve_ip(domain)
        for port in [80,443,8080,8443]:
            proto = "https" if port in [443,8443] else "http"
            url = f"{proto}://{domain}" if port in [80,443] else f"{proto}://{domain}:{port}"
            try:
                r = requests.request("GET", url, timeout=TIMEOUT, verify=False,
                                     allow_redirects=False,
                                     headers={"User-Agent":"Mozilla/5.0 SubScanLTM"})
                code = r.status_code
                cdns = detect_cdn(domain, r)
                cdn_str = ", ".join(cdns)
                tipo, payload, front, nota = generar_payload(domain, cdn_str, port)

                if code in [200,204]:
                    estado = "[bold bright_green]✔ BUG HOST[/bold bright_green]"
                    with lock: results_ok.append({
                        "domain": domain, "ip": ip or "—", "puerto": port,
                        "cdn": cdn_str, "tipo": tipo,
                        "payload": payload, "front": front, "nota": nota
                    })
                elif 300 <= code < 400:
                    estado = "[bright_yellow]➜ REDIRECT[/bright_yellow]"
                else:
                    estado = f"[dim]{code}[/dim]"

                table.add_row(
                    domain, ip or "—", str(port),
                    cdn_str[:14], tipo[:18],
                    front[:20] if front != "—" else "[dim]—[/dim]",
                    estado
                )
                break
            except: pass
        else:
            table.add_row(domain, ip or "—","—","—","—","—","[red]✘ MUERTO[/red]")

    console.print()
    with Progress(SpinnerColumn("dots", style="bright_yellow"),
                  TextColumn("[bright_yellow]{task.description}"),
                  BarColumn(complete_style="bright_green"),
                  TextColumn("[white]{task.completed}[/white][dim]/{task.total}[/dim]"),
                  console=console) as p:
        task = p.add_task("Escaneando hosts...", total=len(targets))
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            for f in concurrent.futures.as_completed({ex.submit(scan,t):t for t in targets}):
                p.advance(task)

    console.print()
    console.print(table)
    console.print(f"\n  [bold bright_green]✔ Bug hosts encontrados: {len(results_ok)}[/bold bright_green]")

    # Mostrar detalles de cada bug host encontrado
    if results_ok:
        console.print()
        console.print("  [bold bright_yellow]◆ DETALLES Y PAYLOADS PARA HTTP CUSTOM[/bold bright_yellow]")
        console.print(f"  [yellow]{'─'*52}[/yellow]")
        for h in results_ok:
            console.print(f"\n  [bold bright_green]► {h['domain']}[/bold bright_green]")
            row("IP",          h['ip'],      "bright_cyan")
            row("Puerto",      str(h['puerto']), "bright_white")
            row("CDN",         h['cdn'],     "bright_magenta")
            row("Tipo de host",h['tipo'],    "bright_yellow")
            row("Domain Front",h['front'],   "bright_cyan")
            row("Nota",        h['nota'],    "dim white")
            console.print(f"\n  [dim white]  Payload HTTP Custom:[/dim white]")
            console.print(f"  [bright_green]  {h['payload']}[/bright_green]")
            separador()

        if ask("Guardar resultados? (s/n)").lower() == "s":
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            contenido = f"SubScanLTM — Creado por {AUTHOR}\nCanal: {CANAL}\n"
            contenido += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            contenido += "=" * 52 + "\n\n"
            for h in results_ok:
                contenido += f"HOST: {h['domain']}\n"
                contenido += f"IP: {h['ip']}\n"
                contenido += f"Puerto: {h['puerto']}\n"
                contenido += f"CDN: {h['cdn']}\n"
                contenido += f"Tipo: {h['tipo']}\n"
                contenido += f"Domain Front: {h['front']}\n"
                contenido += f"Nota: {h['nota']}\n"
                contenido += f"Payload HTTP Custom:\n{h['payload']}\n"
                contenido += "-" * 40 + "\n\n"
            guardar_archivo(f"bughosts_{ts}.txt", contenido)

    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   2. SUBFINDER
# ════════════════════════════════════════════════
def subfinder():
    banner()
    titulo("SUBFINDER  —  Enumeracion de Subdominios")
    domain = clean_domain(ask("Dominio (ej: example.com)"))
    subs = set()

    def crtsh():
        try:
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            for e in r.json():
                for n in e.get("name_value","").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(f".{domain}"): subs.add(n)
        except: pass

    def hackertarget():
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
            for line in r.text.splitlines():
                s = line.split(",")[0].strip().lower()
                if s.endswith(f".{domain}"): subs.add(s)
        except: pass

    def alienvault():
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15, headers={"User-Agent":"Mozilla/5.0"})
            for e in r.json().get("passive_dns",[]):
                h = e.get("hostname","").lower()
                if h.endswith(f".{domain}"): subs.add(h)
        except: pass

    def rapiddns():
        try:
            r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=15,
                             headers={"User-Agent":"Mozilla/5.0"})
            for f in re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text):
                subs.add(f.lower())
        except: pass

    console.print()
    with Progress(SpinnerColumn("dots", style="bright_cyan"),
                  TextColumn("[bright_cyan]Buscando subdominios..."),
                  console=console) as p:
        p.add_task("", total=None)
        threads = [threading.Thread(target=fn) for fn in [crtsh,hackertarget,alienvault,rapiddns]]
        for t in threads: t.start()
        for t in threads: t.join()

    if not subs:
        console.print("  [yellow]⚠ Sin resultados[/yellow]")
        input("\n  Enter..."); return

    # Resolver IP + CDN + cabeceras + payload
    info = {}
    lock2 = threading.Lock()

    def analizar(s):
        ip = resolve_ip(s)
        cnames = []
        servidor = "—"
        codigo   = "—"
        cdn_str  = "Ninguno"
        tipo = payload = front = nota = "—"
        puerto_usado = 80

        # CNAME — fuente mas confiable de CDN
        try:
            cnames = [c.to_text().lower() for c in dns.resolver.resolve(s,"CNAME")]
        except: pass

        # Intentar HTTP request para obtener headers
        for port in [80, 443]:
            proto = "https" if port == 443 else "http"
            try:
                r = requests.get(f"{proto}://{s}", timeout=5, verify=False,
                                 allow_redirects=False,
                                 headers={"User-Agent":"Mozilla/5.0 SubScanLTM"})
                cdns_detectados = detect_cdn(s, r, cnames, ip)
                # Si headers no detectaron CDN pero CNAME o IP si
                if cdns_detectados == ["Ninguno"]:
                    cdns_detectados = detect_cdn(s, cnames=cnames, ip=ip)
                cdn_str  = ", ".join(cdns_detectados)
                servidor = r.headers.get("server", r.headers.get("Server","—"))
                codigo   = str(r.status_code)
                puerto_usado = port
                break
            except:
                # Sin respuesta HTTP — intentar por CNAME e IP
                cdns_por_cname = detect_cdn(s, cnames=cnames, ip=ip)
                if cdns_por_cname != ["Ninguno"]:
                    cdn_str = ", ".join(cdns_por_cname)

        tipo, payload, front, nota = generar_payload(s, cdn_str, puerto_usado)

        with lock2:
            info[s] = {
                "ip": ip, "cdn": cdn_str, "servidor": servidor,
                "codigo": codigo, "tipo": tipo, "payload": payload,
                "front": front, "nota": nota, "puerto": puerto_usado
            }

    console.print()
    with Progress(SpinnerColumn("dots", style="bright_cyan"),
                  TextColumn("[bright_cyan]Analizando subdominios (CDN + cabeceras + payload)..."),
                  BarColumn(complete_style="bright_green"),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("", total=len(subs))
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for f in concurrent.futures.as_completed({ex.submit(analizar,s):s for s in subs}):
                p.advance(task)

    # Tabla minimalista para movil
    console.print()
    for i, s in enumerate(sorted(subs), 1):
        d   = info.get(s, {"ip":None,"cdn":"—"})
        ip  = d["ip"]
        cdn = d["cdn"]
        activo = "[bright_green]✔[/bright_green]" if ip else "[red]✘[/red]"
        console.print(f"  {activo} [bright_white]{s}[/bright_white]")
        console.print(f"    [dim]IP:[/dim] [bright_cyan]{ip or '—'}[/bright_cyan]  [dim]CDN:[/dim] [bright_magenta]{cdn}[/bright_magenta]")

    console.print(f"\n  [bold bright_cyan]◆ Total: {len(subs)} subdominios[/bold bright_cyan]")

    # Detalle completo de cada subdominio activo
    activos = [s for s in sorted(subs) if info.get(s,{}).get("ip")]
    if activos:
        console.print()
        console.print("  [bold bright_yellow]◆ DETALLE — CABECERAS Y PAYLOAD HTTP CUSTOM[/bold bright_yellow]")
        console.print(f"  [yellow]{'─'*52}[/yellow]")
        for s in activos:
            d = info[s]
            console.print(f"\n  [bold bright_green]► {s}[/bold bright_green]")
            row("IP",           d["ip"],       "bright_cyan")
            row("Puerto",       str(d["puerto"]),"bright_white")
            row("Codigo HTTP",  d["codigo"],   "bright_green" if d["codigo"]=="200" else "yellow")
            row("Servidor",     d["servidor"], "bright_white")
            row("CDN",          d["cdn"],      "bright_magenta")
            row("Tipo de host", d["tipo"],     "bright_yellow")
            row("Domain Front", d["front"],    "bright_cyan")
            row("Nota",         d["nota"],     "dim white")
            console.print(f"\n  [dim white]  Payload HTTP Custom:[/dim white]")
            console.print(f"  [bright_green]  {d['payload']}[/bright_green]")
            separador()

    if ask("Guardar? (s/n)").lower() == "s":
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        contenido  = f"SubScanLTM — Subdominios de {domain}\n"
        contenido += f"Creado por {AUTHOR} | {CANAL}\n"
        contenido += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        contenido += "=" * 52 + "\n\n"
        for s in sorted(subs):
            d = info.get(s, {})
            contenido += f"SUBDOMINIO: {s}\n"
            contenido += f"  IP:           {d.get('ip','—')}\n"
            contenido += f"  Codigo HTTP:  {d.get('codigo','—')}\n"
            contenido += f"  Servidor:     {d.get('servidor','—')}\n"
            contenido += f"  CDN:          {d.get('cdn','—')}\n"
            contenido += f"  Tipo host:    {d.get('tipo','—')}\n"
            contenido += f"  Domain Front: {d.get('front','—')}\n"
            contenido += f"  Nota:         {d.get('nota','—')}\n"
            contenido += f"  Payload:\n  {d.get('payload','—')}\n"
            contenido += "-" * 40 + "\n\n"
        guardar_archivo(f"subs_{domain}_{ts}.txt", contenido)

    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   3. IP LOOKUP
# ════════════════════════════════════════════════
def ip_lookup():
    banner()
    titulo("IP LOOKUP  —  Reverse IP & Geolocalizacion")
    target = ask("IP o Dominio")
    ip = target if re.match(r'^\d+\.\d+\.\d+\.\d+$', target) else resolve_ip(target)
    if not ip:
        console.print("  [red]✘ No se pudo resolver[/red]")
        input("\n  Enter..."); return

    console.print(f"\n  [bright_yellow]◆ IP objetivo:[/bright_yellow] [bold bright_white]{ip}[/bold bright_white]\n")
    domains = set()

    def geo():
        try:
            g = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
            console.print("  [bold bright_magenta]◆ Geolocalizacion[/bold bright_magenta]")
            separador()
            row("IP",           g.get("query","—"),  "bright_cyan")
            row("Pais",         g.get("country","—"),"bright_white")
            row("Ciudad",       g.get("city","—"),   "bright_white")
            row("ISP",          g.get("isp","—"),    "bright_yellow")
            row("Organizacion", g.get("org","—"),    "bright_yellow")
            row("AS",           g.get("as","—"),     "dim white")
            separador()
        except: pass

    def rev_ht():
        try:
            r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
            for line in r.text.splitlines():
                d = line.strip().lower()
                if d and "error" not in d: domains.add(d)
        except: pass

    def rev_rapiddns():
        try:
            r = requests.get(f"https://rapiddns.io/s/{ip}?full=1", timeout=15,
                             headers={"User-Agent":"Mozilla/5.0"})
            for f in re.findall(r'[\w\-\.]+\.[\w\-]+\.\w+', r.text):
                if len(f) > 5: domains.add(f.lower())
        except: pass

    with Progress(SpinnerColumn("dots", style="bright_magenta"),
                  TextColumn("[bright_magenta]Consultando fuentes..."), console=console) as p:
        p.add_task("", total=None)
        threads = [threading.Thread(target=fn) for fn in [geo,rev_ht,rev_rapiddns]]
        for t in threads: t.start()
        for t in threads: t.join()

    if domains:
        console.print(f"\n  [bold bright_magenta]◆ Dominios en misma IP ({len(domains)})[/bold bright_magenta]")
        separador()
        table = Table(box=box.ROUNDED, header_style="bold bright_magenta",
                      border_style="magenta", show_lines=False)
        table.add_column("#",       justify="right", style="dim white")
        table.add_column("Dominio", style="bright_white")
        for i, d in enumerate(sorted(domains), 1):
            table.add_row(str(i), d)
        console.print(table)

        if ask("Guardar? (s/n)").lower() == "s":
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            contenido = f"SubScanLTM — Reverse IP: {ip}\nCreado por {AUTHOR} | {CANAL}\n\n"
            contenido += "\n".join(sorted(domains))
            guardar_archivo(f"reverseip_{ip}_{ts}.txt", contenido)
    else:
        console.print("\n  [yellow]⚠ Sin dominios encontrados[/yellow]")
    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   4. PORT SCANNER
# ════════════════════════════════════════════════
def port_scanner():
    banner()
    titulo("PORT SCANNER  —  Puertos Abiertos")
    target = clean_domain(ask("Dominio o IP"))
    ip = resolve_ip(target)
    if not ip:
        console.print("  [red]✘ No se pudo resolver[/red]")
        input("\n  Enter..."); return

    modo = ask("Puertos:  [1] Comunes   [2] Personalizados")
    if modo == "2":
        raw = ask("Puertos separados por coma (ej: 80,443,8080)")
        ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
    else:
        ports = COMMON_PORTS

    console.print(f"\n  [dim white]IP: {ip}  |  {len(ports)} puertos[/dim white]\n")
    open_ports = []
    lock = threading.Lock()

    def scan(port):
        try:
            s = socket.socket(); s.settimeout(2)
            if s.connect_ex((ip, port)) == 0:
                with lock: open_ports.append(port)
            s.close()
        except: pass

    with Progress(SpinnerColumn("dots", style="bright_yellow"),
                  TextColumn("[bright_yellow]Escaneando puertos..."),
                  BarColumn(complete_style="bright_green"),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("", total=len(ports))
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            for f in concurrent.futures.as_completed({ex.submit(scan,port):port for port in ports}):
                p.advance(task)

    console.print()
    if open_ports:
        table = Table(box=box.ROUNDED, header_style="bold bright_yellow",
                      border_style="yellow", show_lines=False)
        table.add_column("Puerto",   justify="right", style="bold bright_green")
        table.add_column("Servicio", style="bright_cyan")
        for port in sorted(open_ports):
            table.add_row(str(port), PORT_NAMES.get(port,"Unknown"))
        console.print(table)
        console.print(f"\n  [bold bright_green]✔ {len(open_ports)} puertos abiertos[/bold bright_green]")
    else:
        console.print("  [red]✘ Sin puertos abiertos[/red]")
    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   5. DNS RECORDS
# ════════════════════════════════════════════════
def dns_records():
    banner()
    titulo("DNS RECORDS  —  Registros del Dominio")
    domain = clean_domain(ask("Dominio"))
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    cnames = []
    found = False
    COLORS = {"A":"bright_green","AAAA":"bright_cyan","CNAME":"bright_yellow",
              "MX":"bright_magenta","NS":"bright_blue","TXT":"white","SOA":"dim white"}
    for rtype in ["A","AAAA","CNAME","MX","NS","TXT","SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            color = COLORS.get(rtype,"white")
            console.print(f"\n  [bold {color}]◆ {rtype}[/bold {color}]")
            separador()
            for r in answers:
                val = r.to_text()
                if rtype == "CNAME": cnames.append(val.lower())
                row("->", val, color)
            separador()
            found = True
        except: pass
    if not found:
        console.print("  [yellow]⚠ Sin registros DNS[/yellow]")
    if cnames:
        cdn = ", ".join(detect_cdn(domain, cnames=cnames))
        console.print(f"\n  [dim white]CDN por CNAME:[/dim white] [bright_magenta]{cdn}[/bright_magenta]")
    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   6. HOST INFO
# ════════════════════════════════════════════════
def host_info():
    banner()
    titulo("HOST INFO  —  Analisis Completo del Host")
    domain = clean_domain(ask("Dominio"))
    ip = resolve_ip(domain)

    if ip:
        console.print(f"\n  [bold bright_white]◆ Red & Geo[/bold bright_white]")
        separador()
        row("Dominio", domain, "bright_cyan")
        row("IP",      ip,     "bright_green")
        try:
            g = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
            row("Pais", g.get("country","—"),  "bright_white")
            row("ISP",  g.get("isp","—"),      "bright_yellow")
            row("AS",   g.get("as","—"),        "dim white")
        except: pass
        separador()

    for proto in ["https","http"]:
        r = http_get(f"{proto}://{domain}")
        if r:
            console.print(f"\n  [bold bright_green]◆ HTTP {proto.upper()}[/bold bright_green]")
            separador()
            code = r.status_code
            row("Codigo",        str(code), "bright_green" if code==200 else "bright_yellow")
            row("Servidor",      r.headers.get("server","—"), "bright_white")
            row("X-Powered-By",  r.headers.get("x-powered-by","—"), "dim white")
            cnames = []
            try: cnames = [c.to_text().lower() for c in dns.resolver.resolve(domain,"CNAME")]
            except: pass
            cdns = detect_cdn(domain, r, cnames)
            cdn_str = ", ".join(cdns)
            row("CDN", cdn_str, "bright_magenta")

            # Payload sugerido
            tipo, payload, front, nota = generar_payload(domain, cdn_str, 443 if proto=="https" else 80)
            row("Tipo de host",  tipo,    "bright_cyan")
            row("Domain Front",  front,   "bright_yellow")
            row("Payload",       payload[:50]+"...", "dim green")
            separador()

            console.print(f"\n  [bold bright_blue]◆ Headers de Seguridad[/bold bright_blue]")
            separador()
            for h in ["strict-transport-security","x-frame-options",
                      "x-xss-protection","content-security-policy","x-content-type-options"]:
                val = r.headers.get(h)
                row(h[:25], val[:50] if val else "Ausente",
                    "bright_green" if val else "red")
            separador()
            break

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT); s.connect((domain,443))
            cert = s.getpeercert()
            console.print(f"\n  [bold bright_cyan]◆ SSL/TLS[/bold bright_cyan]")
            separador()
            subj   = dict(x[0] for x in cert.get("subject",[]))
            issuer = dict(x[0] for x in cert.get("issuer",[]))
            row("Comun",  subj.get("commonName","—"),          "bright_white")
            row("Emisor", issuer.get("organizationName","—"),  "bright_yellow")
            row("Expira", cert.get("notAfter","—"),            "bright_green")
            sans = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
            row("SANs",   f"{len(sans)} dominios",             "bright_cyan")
            separador()
    except:
        console.print("  [dim red]SSL no disponible[/dim red]")

    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   7. FULL SCAN
# ════════════════════════════════════════════════
def full_scan():
    banner()
    titulo("FULL SCAN  —  Analisis Completo")
    domain = clean_domain(ask("Dominio objetivo"))
    ip = resolve_ip(domain)
    console.print(f"\n  [bold bright_yellow]◆ Objetivo:[/bold bright_yellow] [bright_white]{domain}[/bright_white]  [dim]({ip or 'sin IP'})[/dim]\n")

    console.rule("[bold bright_magenta]GEO[/bold bright_magenta]")
    try:
        g = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        row("IP",   ip or "—",          "bright_cyan")
        row("Pais", g.get("country","—"),"bright_white")
        row("ISP",  g.get("isp","—"),    "bright_yellow")
    except: pass

    console.rule("[bold bright_green]HTTP & CDN[/bold bright_green]")
    cdn_str = "Ninguno"
    for proto in ["https","http"]:
        r = http_get(f"{proto}://{domain}")
        if r:
            cnames = []
            try: cnames = [c.to_text().lower() for c in dns.resolver.resolve(domain,"CNAME")]
            except: pass
            cdns = detect_cdn(domain, r, cnames)
            cdn_str = ", ".join(cdns)
            row("Codigo",  str(r.status_code), "bright_green" if r.status_code==200 else "yellow")
            row("Servidor",r.headers.get("server","—"), "bright_white")
            row("CDN",     cdn_str, "bright_magenta")
            puerto = 443 if proto=="https" else 80
            tipo, payload, front, nota = generar_payload(domain, cdn_str, puerto)
            row("Tipo host", tipo,  "bright_cyan")
            row("Front",     front, "bright_yellow")
            break

    console.rule("[bold bright_blue]DNS[/bold bright_blue]")
    resolver = dns.resolver.Resolver(); resolver.timeout = 4
    for rtype in ["A","CNAME","MX","NS"]:
        try:
            for r in resolver.resolve(domain, rtype):
                row(rtype, r.to_text()[:55], "bright_green" if rtype=="A" else "bright_white")
        except: pass

    console.rule("[bold bright_cyan]SSL[/bold bright_cyan]")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT); s.connect((domain,443))
            cert = s.getpeercert()
            subj = dict(x[0] for x in cert.get("subject",[]))
            row("CN",     subj.get("commonName","—"), "bright_white")
            row("Expira", cert.get("notAfter","—"),   "bright_green")
    except: console.print("  [dim red]SSL no disponible[/dim red]")

    console.rule("[bold bright_yellow]SUBDOMINIOS[/bold bright_yellow]")
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        for e in r.json():
            for n in e.get("name_value","").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(f".{domain}"): subs.add(n)
    except: pass
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        for line in r.text.splitlines():
            s = line.split(",")[0].strip().lower()
            if s.endswith(f".{domain}"): subs.add(s)
    except: pass
    console.print(f"  [bright_green]{len(subs)} subdominios encontrados[/bright_green]")
    for s in sorted(subs)[:15]: row("->", s, "dim white")
    if len(subs) > 15: console.print(f"  [dim]  ... y {len(subs)-15} mas[/dim]")

    console.rule("[bold bright_yellow]PUERTOS[/bold bright_yellow]")
    open_ports = []
    lock = threading.Lock()
    def sp(port):
        try:
            s = socket.socket(); s.settimeout(2)
            if s.connect_ex((ip,port))==0:
                with lock: open_ports.append(port)
            s.close()
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(sp, [22,80,443,1080,3128,8080,8443,3389,8888])
    for p in sorted(open_ports):
        row(f"Puerto {p}", f"{PORT_NAMES.get(p,'?')}  ABIERTO", "bright_green")
    if not open_ports: console.print("  [dim]Sin puertos clave abiertos[/dim]")

    console.rule("[bold bright_yellow]FULL SCAN COMPLETADO[/bold bright_yellow]")

    if ask("Guardar reporte? (s/n)").lower() == "s":
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        contenido  = f"SubScanLTM — Full Scan\nCreado por {AUTHOR} | {CANAL}\n"
        contenido += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        contenido += "=" * 52 + "\n"
        contenido += f"Dominio: {domain}\nIP: {ip}\nCDN: {cdn_str}\n"
        contenido += f"\nSubdominios ({len(subs)}):\n" + "\n".join(sorted(subs))
        contenido += f"\nPuertos abiertos: {open_ports}\n"
        guardar_archivo(f"fullscan_{domain}_{ts}.txt", contenido)

    input("\n  Enter para continuar...")


# ════════════════════════════════════════════════
#   MAIN
# ════════════════════════════════════════════════
def main():
    while True:
        choice = menu()
        actions = {"1":host_scanner,"2":subfinder,"3":ip_lookup,
                   "4":port_scanner,"5":dns_records,"6":host_info,"7":full_scan}
        if choice == "0":
            console.print(f"\n  [bright_yellow]◆ Hasta luego![/bright_yellow]")
            console.print(f"  [dim]Creado por {AUTHOR}  |  {CANAL}[/dim]\n")
            sys.exit(0)
        elif choice in actions:
            actions[choice]()
        else:
            console.print("  [red]✘ Opcion invalida[/red]")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Saliendo...[/yellow]\n")
        sys.exit(0)
