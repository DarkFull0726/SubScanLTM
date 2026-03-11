#!/usr/bin/env python3
# ════════════════════════════════════════════════
#   SubScanLTM — Bug Host Intelligence Tool
#   Creado por @DarkZFull
#   Canal: https://t.me/ltmdkz
# ════════════════════════════════════════════════

import os, sys, subprocess

DEPS = ["requests", "dnspython", "rich", "colorama"]

def auto_install():
    missing = []
    for dep in DEPS:
        try: __import__(dep.replace("-","_"))
        except ImportError: missing.append(dep)
    if missing:
        print(f"\n  ◈ Instalando: {', '.join(missing)}...")
        for dep in missing:
            subprocess.run([sys.executable,"-m","pip","install",dep,"-q"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("  ◈ Listo\n")

auto_install()

import socket, ssl, re, time, threading
import concurrent.futures
from datetime import datetime

import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
import colorama
colorama.init()

requests.packages.urllib3.disable_warnings()
console = Console()

VERSION = "1.2.0"
AUTHOR  = "@DarkZFull"
CANAL   = "https://t.me/ltmdkz"
SUBTITULO = "Escaner de subdominios y bug hosts"
TIMEOUT = 8
THREADS = 50

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
    return console.input(f"  [bold yellow]  ❯[/bold yellow] {prompt}: ").strip()

def row(label, value, color="bright_white"):
    console.print(f"  [dim white]  {label:<22}[/dim white][{color}]{value}[/{color}]")

def titulo(texto):
    console.print(f"\n  [bold yellow]◆[/bold yellow] [bold bright_white]{texto}[/bold bright_white]")
    console.print(f"  [yellow]{'─'*50}[/yellow]")

def separador():
    console.print(f"  [dim yellow]{'─'*50}[/dim yellow]")

def http_get(url):
    try:
        return requests.get(url, timeout=TIMEOUT, verify=False,
                            allow_redirects=True,
                            headers={"User-Agent":"Mozilla/5.0 SubScanLTM"})
    except: return None

def detect_cdn(domain, response=None, cnames=None):
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
    return found if found else ["Ninguno"]

# ════════════════════════════════════════════════
#   BANNER
# ════════════════════════════════════════════════
def banner():
    cls()
    # Arte distinto — letras bloque estilo "S S L"
    console.print()
    console.print("  [bold bright_yellow] ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄[/bold bright_yellow]")
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][bold bright_white]  SubScan[/bold bright_white][bold bright_green]LTM[/bold bright_green][bold bright_yellow]                           ██[/bold bright_yellow]")
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Escaner de subdominios y bug hosts  v{:<4}[/dim white][bold bright_yellow]██[/bold bright_yellow]".format(VERSION))
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Creado por [/dim white][bold bright_green]{:<10}[/bold bright_green][dim white]                [/dim white][bold bright_yellow]██[/bold bright_yellow]".format(AUTHOR))
    console.print("  [bold bright_yellow] ██[/bold bright_yellow][dim white]  Canal: [/dim white][bold bright_cyan]{:<20}[/bold bright_cyan][dim white]          [/dim white][bold bright_yellow]██[/bold bright_yellow]".format(CANAL))
    console.print("  [bold bright_yellow] ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/bold bright_yellow]")
    console.print()

def menu():
    banner()
    console.print("  [bold bright_green]  MENU PRINCIPAL[/bold bright_green]")
    console.print("  [dim yellow]  ══════════════════════════════════════[/dim yellow]")
    console.print()

    opciones = [
        ("1", "HOST SCANNER",  "bright_green",  "Detecta bug hosts HTTP/HTTPS"),
        ("2", "SUBFINDER",     "bright_cyan",   "Enumera subdominios"),
        ("3", "IP LOOKUP",     "bright_magenta","Reverse IP + geolocalizacion"),
        ("4", "PORT SCANNER",  "bright_yellow", "Escanea puertos abiertos"),
        ("5", "DNS RECORDS",   "bright_blue",   "Registros A, MX, NS, TXT..."),
        ("6", "HOST INFO",     "bright_white",  "CDN, servidor, SSL, geo"),
        ("7", "FULL SCAN",     "bold bright_red","Todo en uno sobre un dominio"),
        ("0", "SALIR",         "dim red",       ""),
    ]

    for num, name, color, desc in opciones:
        if num == "0":
            console.print(f"  [dim]  [{num}][/dim]  [{color}]{name}[/{color}]")
        else:
            console.print(f"  [bold bright_yellow]  [{num}][/bold bright_yellow]  [{color}]{name:<18}[/{color}][dim white]{desc}[/dim white]")

    console.print()
    console.print("  [dim yellow]  ══════════════════════════════════════[/dim yellow]")
    return console.input(f"\n  [bold bright_yellow]  ❯[/bold bright_yellow] Opcion: ").strip()

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
    table.add_column("Codigo",   justify="center")
    table.add_column("Servidor", style="dim", max_width=16)
    table.add_column("CDN",      style="bright_magenta", max_width=16)
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
                server = r.headers.get("server","—")
                cdn = ", ".join(detect_cdn(domain, r))
                if code in [200,204]:
                    estado = "[bold bright_green]✔ BUG HOST[/bold bright_green]"
                    with lock: results_ok.append(domain)
                elif 300 <= code < 400:
                    estado = "[bright_yellow]➜ REDIRECT[/bright_yellow]"
                else:
                    estado = f"[dim]{code}[/dim]"
                table.add_row(domain, ip or "—", str(port), str(code), server[:16], cdn[:16], estado)
                break
            except: pass
        else:
            table.add_row(domain, ip or "—","—","—","—","—","[red]✘ MUERTO[/red]")

    console.print()
    with Progress(SpinnerColumn("dots", style="bright_yellow"),
                  TextColumn("[bright_yellow]{task.description}"),
                  BarColumn(complete_style="bright_green", finished_style="green"),
                  TextColumn("[white]{task.completed}[/white][dim]/{task.total}[/dim]"),
                  console=console) as p:
        task = p.add_task("Escaneando hosts...", total=len(targets))
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            for f in concurrent.futures.as_completed({ex.submit(scan,t):t for t in targets}):
                p.advance(task)

    console.print()
    console.print(table)
    console.print(f"\n  [bold bright_green]✔ Bug hosts: {len(results_ok)}[/bold bright_green]")

    if results_ok and ask("Guardar resultados? (s/n)").lower() == "s":
        fname = f"bughosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(os.path.expanduser(f"~/{fname}"), "w") as f:
            f.write("\n".join(results_ok))
        console.print(f"  [bright_green]✔ Guardado:[/bright_green] ~/{fname}")
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
                  TextColumn("[bright_cyan]Buscando subdominios de {task.description}"),
                  console=console) as p:
        p.add_task(domain, total=None)
        threads = [threading.Thread(target=fn) for fn in [crtsh,hackertarget,alienvault,rapiddns]]
        for t in threads: t.start()
        for t in threads: t.join()

    if not subs:
        console.print("  [yellow]⚠ Sin resultados[/yellow]")
        input("\n  Enter..."); return

    ips = {}
    def res(s): ips[s] = resolve_ip(s)
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        ex.map(res, subs)

    table = Table(box=box.ROUNDED, header_style="bold bright_cyan",
                  border_style="cyan", show_lines=False)
    table.add_column("#",          justify="right", style="dim white")
    table.add_column("Subdominio", style="bright_white")
    table.add_column("IP",         style="bright_cyan")
    table.add_column("Activo",     justify="center")
    for i, s in enumerate(sorted(subs), 1):
        ip = ips.get(s)
        table.add_row(str(i), s, ip or "—",
                      "[bold bright_green]SI[/bold bright_green]" if ip else "[dim red]NO[/dim red]")
    console.print(table)
    console.print(f"\n  [bold bright_cyan]◆ Total: {len(subs)} subdominios[/bold bright_cyan]")

    if ask("Guardar? (s/n)").lower() == "s":
        fname = f"subs_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(os.path.expanduser(f"~/{fname}"), "w") as f:
            f.write("\n".join(sorted(subs)))
        console.print(f"  [bright_green]✔ Guardado:[/bright_green] ~/{fname}")
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
            row("IP",            g.get("query","—"),    "bright_cyan")
            row("Pais",          g.get("country","—"),  "bright_white")
            row("Ciudad",        g.get("city","—"),     "bright_white")
            row("ISP",           g.get("isp","—"),      "bright_yellow")
            row("Organizacion",  g.get("org","—"),      "bright_yellow")
            row("AS",            g.get("as","—"),       "dim white")
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
            fname = f"reverseip_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(os.path.expanduser(f"~/{fname}"), "w") as f:
                f.write("\n".join(sorted(domains)))
            console.print(f"  [bright_green]✔ Guardado:[/bright_green] ~/{fname}")
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

    console.print(f"\n  [dim white]IP: {ip}  |  {len(ports)} puertos objetivo[/dim white]\n")
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
                  TextColumn("[white]{task.completed}[/white][dim]/{task.total}[/dim]"),
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
                row("→", val, color)
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
            row("Codigo",       str(code), "bright_green" if code==200 else "bright_yellow")
            row("Servidor",     r.headers.get("server","—"),       "bright_white")
            row("X-Powered-By", r.headers.get("x-powered-by","—"),"dim white")
            cnames = []
            try: cnames = [c.to_text().lower() for c in dns.resolver.resolve(domain,"CNAME")]
            except: pass
            cdn = ", ".join(detect_cdn(domain, r, cnames))
            row("CDN", cdn, "bright_magenta")
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
            console.print(f"\n  [bold bright_cyan]◆ Certificado SSL/TLS[/bold bright_cyan]")
            separador()
            subj   = dict(x[0] for x in cert.get("subject",[]))
            issuer = dict(x[0] for x in cert.get("issuer",[]))
            row("Comun",  subj.get("commonName","—"),           "bright_white")
            row("Emisor", issuer.get("organizationName","—"),   "bright_yellow")
            row("Expira", cert.get("notAfter","—"),             "bright_green")
            sans = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
            row("SANs",   f"{len(sans)} dominios cubiertos",   "bright_cyan")
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

    # GEO
    console.print("  [bold bright_magenta]━━  GEO & RED  ━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold bright_magenta]")
    try:
        g = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        row("IP",   ip or "—",          "bright_cyan")
        row("Pais", g.get("country","—"),"bright_white")
        row("ISP",  g.get("isp","—"),    "bright_yellow")
    except: pass

    # HTTP
    console.print("\n  [bold bright_green]━━  HTTP & CDN  ━━━━━━━━━━━━━━━━━━━━━━━━━[/bold bright_green]")
    for proto in ["https","http"]:
        r = http_get(f"{proto}://{domain}")
        if r:
            cnames = []
            try: cnames = [c.to_text().lower() for c in dns.resolver.resolve(domain,"CNAME")]
            except: pass
            row("Codigo",  str(r.status_code), "bright_green" if r.status_code==200 else "yellow")
            row("Servidor",r.headers.get("server","—"), "bright_white")
            row("CDN",     ", ".join(detect_cdn(domain, r, cnames)), "bright_magenta")
            break

    # DNS
    console.print("\n  [bold bright_blue]━━  DNS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold bright_blue]")
    resolver = dns.resolver.Resolver(); resolver.timeout = 4
    for rtype in ["A","CNAME","MX","NS"]:
        try:
            for r in resolver.resolve(domain, rtype):
                row(rtype, r.to_text()[:55], "bright_green" if rtype=="A" else "bright_white")
        except: pass

    # SSL
    console.print("\n  [bold bright_cyan]━━  SSL  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold bright_cyan]")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT); s.connect((domain,443))
            cert = s.getpeercert()
            subj = dict(x[0] for x in cert.get("subject",[]))
            row("CN",     subj.get("commonName","—"),  "bright_white")
            row("Expira", cert.get("notAfter","—"),    "bright_green")
    except: console.print("  [dim red]SSL no disponible[/dim red]")

    # SUBDOMINIOS
    console.print("\n  [bold bright_yellow]━━  SUBDOMINIOS  ━━━━━━━━━━━━━━━━━━━━━━━━[/bold bright_yellow]")
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
    console.print(f"  [bold bright_green]✔ {len(subs)} subdominios encontrados[/bold bright_green]")
    for s in sorted(subs)[:15]: row("→", s, "dim white")
    if len(subs) > 15: console.print(f"  [dim]  ... y {len(subs)-15} mas[/dim]")

    # PUERTOS
    console.print("\n  [bold bright_yellow]━━  PUERTOS CLAVE  ━━━━━━━━━━━━━━━━━━━━━━[/bold bright_yellow]")
    open_ports = []
    lock = threading.Lock()
    key_ports = [22,80,443,1080,3128,8080,8443,3389,8888]
    def sp(port):
        try:
            s = socket.socket(); s.settimeout(2)
            if s.connect_ex((ip,port))==0:
                with lock: open_ports.append(port)
            s.close()
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(sp, key_ports)
    for p in sorted(open_ports):
        row(f"Puerto {p}", f"{PORT_NAMES.get(p,'?')}  ●  ABIERTO", "bright_green")
    if not open_ports: console.print("  [dim]Sin puertos clave abiertos[/dim]")

    console.print(f"\n  [bold bright_yellow]◆ FULL SCAN COMPLETADO  ✔[/bold bright_yellow]\n")

    if ask("Guardar reporte? (s/n)").lower() == "s":
        fname = f"fullscan_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(os.path.expanduser(f"~/{fname}"), "w") as f:
            f.write(f"SubScanLTM — Creado por {AUTHOR}\nCanal: {CANAL}\n\n")
            f.write(f"Dominio: {domain}\nIP: {ip}\n")
            f.write(f"\nSubdominios ({len(subs)}):\n" + "\n".join(sorted(subs)))
            f.write(f"\nPuertos abiertos: {open_ports}\n")
        console.print(f"  [bright_green]✔ Guardado:[/bright_green] ~/{fname}")
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
            console.print(f"\n  [bright_yellow]◆ Hasta luego! — SubScanLTM[/bright_yellow]")
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
