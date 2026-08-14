#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
import json
import secrets
from urllib.parse import quote
from aiohttp import web

CONFIG_FILE = os.environ.get("CONFIG_FILE", "settings.json")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
UUID = os.environ.get("UUID", "7bd180e8-142f-4387-93f5-03e8d750a896")
NEZHA_SERVER = os.environ.get("NEZHA_SERVER", "")
NEZHA_PORT = os.environ.get("NEZHA_PORT", "")
NEZHA_KEY = os.environ.get("NEZHA_KEY", "")
DOMAIN = os.environ.get("DOMAIN", "")
SUB_PATH = os.environ.get("SUB_PATH", "sub")
NAME = os.environ.get("NAME", "")
WSPATH = os.environ.get("WSPATH", UUID[:8])
PORT = int(os.environ.get("SERVER_PORT") or os.environ.get("PORT") or 3000)
AUTO_ACCESS = os.environ.get("AUTO_ACCESS", "").lower() == "true"
DEBUG = os.environ.get("DEBUG", "").lower() == "true"

DEFAULT_SETTINGS = {
    "domain": DOMAIN,
    "public_port": 443 if DOMAIN else PORT,
    "tls": bool(DOMAIN),
    "name": NAME or "Limo Node",
    "ws_path": WSPATH,
    "uuid": UUID,
    "protocols": {
        "vless": True,
        "trojan": True,
        "shadowsocks": True
    }
}

settings = {}
config_lock = asyncio.Lock()

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
for name in (
    "aiohttp.access", "aiohttp.server", "aiohttp.client",
    "aiohttp.internal", "aiohttp.websocket"
):
    logging.getLogger(name).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

DNS_SERVERS = ["8.8.4.4", "1.1.1.1"]
BLOCKED_DOMAINS = {
    "speedtest.net", "fast.com", "speedtest.cn", "speed.cloudflare.com",
    "speedof.me", "testmy.net", "bandwidth.place", "speed.io",
    "librespeed.org", "speedcheck.org"
}

def save_settings():
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONFIG_FILE)

def normalize_settings(data):
    out = DEFAULT_SETTINGS.copy()
    out["protocols"] = DEFAULT_SETTINGS["protocols"].copy()
    if isinstance(data, dict):
        out.update({k: v for k, v in data.items() if k != "protocols"})
        if isinstance(data.get("protocols"), dict):
            out["protocols"].update({
                k: bool(v) for k, v in data["protocols"].items()
                if k in out["protocols"]
            })
    out["domain"] = str(out["domain"]).strip()
    out["name"] = str(out["name"]).strip() or "Limo Node"
    out["ws_path"] = str(out["ws_path"]).strip().strip("/") or WSPATH
    out["uuid"] = str(out["uuid"]).strip() or UUID
    try:
        out["public_port"] = max(1, min(65535, int(out["public_port"])))
    except (TypeError, ValueError):
        out["public_port"] = 443 if out["tls"] else PORT
    out["tls"] = bool(out["tls"])
    return out

def load_settings():
    global settings
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                settings = normalize_settings(json.load(f))
                return
        except Exception as e:
            logger.warning("Could not read settings.json: %s", e)
    settings = normalize_settings({})
    save_settings()

def is_port_available(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host):
    host = (host or "").lower().rstrip(".")
    return any(host == x or host.endswith("." + x) for x in BLOCKED_DOMAINS)

async def get_isp():
    for url, country_key, isp_key in (
        ("https://api.ip.sb/geoip", "country_code", "isp"),
        ("http://ip-api.com/json", "countryCode", "org"),
    ):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=3
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return f"{data.get(country_key, '')}-{data.get(isp_key, '')}".replace(" ", "_")
        except Exception:
            pass
    return "Unknown"

async def get_public_ip():
    if settings["domain"]:
        return settings["domain"]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api-ipv4.ip.sb/ip", timeout=5) as resp:
                if resp.status == 200:
                    return (await resp.text()).strip()
    except Exception:
        pass
    return "change-your-domain.com"

async def resolve_host(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://dns.google/resolve?name={quote(host)}&type=A"
            async with session.get(url, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for answer in data.get("Answer", []):
                        if answer.get("type") == 1:
                            return answer.get("data")
    except Exception:
        pass
    return host

async def pipe_tcp_ws(websocket, reader, writer):
    async def ws_to_tcp():
        try:
            async for msg in websocket:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
        except Exception:
            pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                await websocket.send_bytes(data)
        except Exception:
            pass

    try:
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

def parse_target(data, offset, address_types):
    if offset >= len(data):
        raise ValueError("missing address type")
    atyp = data[offset]
    offset += 1

    if atyp == address_types["ipv4"]:
        if offset + 4 > len(data):
            raise ValueError("short ipv4")
        host = ".".join(map(str, data[offset:offset + 4]))
        offset += 4
    elif atyp == address_types["domain"]:
        if offset >= len(data):
            raise ValueError("missing domain length")
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise ValueError("short domain")
        host = data[offset:offset + length].decode("utf-8", "ignore")
        offset += length
    elif atyp == address_types["ipv6"]:
        if offset + 16 > len(data):
            raise ValueError("short ipv6")
        host = ":".join(
            f"{(data[i] << 8) + data[i + 1]:04x}"
            for i in range(offset, offset + 16, 2)
        )
        offset += 16
    else:
        raise ValueError("unknown address type")

    if offset + 2 > len(data):
        raise ValueError("missing port")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    return host, port, offset

class ProxyHandler:
    def __init__(self, uuid_text):
        self.uuid = uuid_text.replace("-", "")
        self.uuid_bytes = bytes.fromhex(self.uuid)

    async def connect_and_pipe(self, websocket, host, port, remaining):
        if is_blocked_domain(host):
            await websocket.close()
            return False
        resolved = await resolve_host(host)
        try:
            reader, writer = await asyncio.open_connection(resolved, port)
            if remaining:
                writer.write(remaining)
                await writer.drain()
            await pipe_tcp_ws(websocket, reader, writer)
            return True
        except Exception as e:
            if DEBUG:
                logger.error("Connection error: %s", e)
            return False

    async def handle_vless(self, websocket, first_msg):
        if len(first_msg) < 18 or first_msg[0] != 0:
            return False
        if first_msg[1:17] != self.uuid_bytes:
            return False
        try:
            offset = first_msg[17] + 19
            host, port, offset = parse_target(
                first_msg, offset, {"ipv4": 1, "domain": 2, "ipv6": 3}
            )
            await websocket.send_bytes(b"\x00\x00")
            return await self.connect_and_pipe(websocket, host, port, first_msg[offset:])
        except Exception as e:
            if DEBUG:
                logger.error("VLESS handler error: %s", e)
            return False

    async def handle_trojan(self, websocket, first_msg):
        if len(first_msg) < 58:
            return False
        try:
            received = first_msg[:56].decode("ascii", "ignore")
            valid = {
                hashlib.sha224(self.uuid.encode()).hexdigest(),
                hashlib.sha224(self.uuid.replace("-", "").encode()).hexdigest()
            }
            if received not in valid:
                return False
            offset = 56
            if first_msg[offset:offset + 2] == b"\r\n":
                offset += 2
            if offset >= len(first_msg) or first_msg[offset] != 1:
                return False
            offset += 1
            host, port, offset = parse_target(
                first_msg, offset, {"ipv4": 1, "domain": 3, "ipv6": 4}
            )
            if first_msg[offset:offset + 2] == b"\r\n":
                offset += 2
            return await self.connect_and_pipe(websocket, host, port, first_msg[offset:])
        except Exception as e:
            if DEBUG:
                logger.error("Trojan handler error: %s", e)
            return False

    async def handle_shadowsocks(self, websocket, first_msg):
        if len(first_msg) < 7:
            return False
        try:
            host, port, offset = parse_target(
                first_msg, 0, {"ipv4": 1, "domain": 3, "ipv6": 4}
            )
            return await self.connect_and_pipe(websocket, host, port, first_msg[offset:])
        except Exception as e:
            if DEBUG:
                logger.error("Shadowsocks handler error: %s", e)
            return False

async def websocket_handler(request):
    async with config_lock:
        path = settings["ws_path"]
        uuid_text = settings["uuid"]

    if request.path.strip("/") != path:
        return web.Response(status=404, text="Not Found")

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    proxy = ProxyHandler(uuid_text)

    try:
        first = await asyncio.wait_for(ws.receive(), timeout=5)
        if first.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws

        data = first.data
        async with config_lock:
            protocols = settings["protocols"].copy()

        if protocols["vless"] and len(data) > 17 and data[0] == 0:
            if await proxy.handle_vless(ws, data):
                return ws
        if protocols["trojan"] and len(data) >= 58:
            if await proxy.handle_trojan(ws, data):
                return ws
        if protocols["shadowsocks"] and data and data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, data):
                return ws

        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error("WebSocket handler error: %s", e)
        await ws.close()
    return ws

async def build_configs():
    async with config_lock:
        cfg = json.loads(json.dumps(settings))

    domain = cfg["domain"] or await get_public_ip()
    port = cfg["public_port"]
    tls = cfg["tls"]
    security = "tls" if tls else "none"
    name = cfg["name"]
    ws_path = cfg["ws_path"]
    uuid = cfg["uuid"]

    configs = []
    if cfg["protocols"]["vless"]:
        vless = (
            f"vless://{uuid}@{domain}:{port}"
            f"?encryption=none&security={security}"
            f"&sni={quote(domain)}&fp=chrome&type=ws"
            f"&host={quote(domain)}&path=%2F{quote(ws_path)}"
            f"#{quote(name + ' VLESS')}"
        )
        configs.append({"protocol": "VLESS", "url": vless})

    if cfg["protocols"]["trojan"]:
        trojan = (
            f"trojan://{uuid}@{domain}:{port}"
            f"?security={security}&sni={quote(domain)}"
            f"&fp=chrome&type=ws&host={quote(domain)}"
            f"&path=%2F{quote(ws_path)}#{quote(name + ' Trojan')}"
        )
        configs.append({"protocol": "Trojan", "url": trojan})

    if cfg["protocols"]["shadowsocks"]:
        password = base64.b64encode(f"none:{uuid}".encode()).decode()
        tls_part = "tls;" if tls else ""
        ss = (
            f"ss://{password}@{domain}:{port}"
            f"?plugin=v2ray-plugin;mode%3Dwebsocket;"
            f"host%3D{quote(domain)};path%3D%2F{quote(ws_path)};"
            f"{tls_part}sni%3D{quote(domain)};skip-cert-verify%3Dtrue;mux%3D0"
            f"#{quote(name + ' Shadowsocks')}"
        )
        configs.append({"protocol": "Shadowsocks", "url": ss})

    return configs

def auth_ok(request):
    if not ADMIN_KEY:
        return True
    supplied = request.headers.get("X-Admin-Key", "")
    if supplied == ADMIN_KEY:
        return True
    supplied = request.query.get("key", "")
    return secrets.compare_digest(supplied, ADMIN_KEY)

async def dashboard(request):
    if not auth_ok(request):
        return web.Response(status=401, text="Unauthorized")
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return web.Response(text=f.read(), content_type="text/html")
    except OSError:
        return web.Response(status=500, text="index.html is missing")

async def api_settings_get(request):
    if not auth_ok(request):
        return web.json_response({"error": "Unauthorized"}, status=401)
    async with config_lock:
        data = json.loads(json.dumps(settings))
    data["listen_port"] = PORT
    data["admin_password_enabled"] = bool(ADMIN_KEY)
    data["protocol_count"] = sum(data["protocols"].values())
    return web.json_response(data)

async def api_settings_post(request):
    if not auth_ok(request):
        return web.json_response({"error": "Unauthorized"}, status=401)
    try:
        incoming = await request.json()
        async with config_lock:
            updated = normalize_settings({
                **settings,
                "domain": incoming.get("domain", settings["domain"]),
                "public_port": incoming.get("public_port", settings["public_port"]),
                "tls": incoming.get("tls", settings["tls"]),
                "name": incoming.get("name", settings["name"]),
                "ws_path": incoming.get("ws_path", settings["ws_path"]),
                "uuid": incoming.get("uuid", settings["uuid"]),
                "protocols": incoming.get("protocols", settings["protocols"])
            })
            settings.clear()
            settings.update(updated)
            save_settings()
        return web.json_response({
            "ok": True,
            "message": "Settings saved",
            "restart_required_for_listen_port": incoming.get("listen_port") not in (None, PORT)
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

async def api_configs(request):
    if not auth_ok(request):
        return web.json_response({"error": "Unauthorized"}, status=401)
    configs = await build_configs()
    return web.json_response({
        "count": len(configs),
        "configs": configs
    })

async def http_handler(request):
    if request.path == "/":
        return await dashboard(request)

    async with config_lock:
        sub_path = SUB_PATH

    if request.path == f"/{sub_path}":
        configs = await build_configs()
        subscription = "\n".join(x["url"] for x in configs)
        return web.Response(
            text=base64.b64encode(subscription.encode()).decode() + "\n",
            content_type="text/plain"
        )

    return web.Response(status=404, text="Not Found\n")

# ---------------- Nezha: kept from the original app ----------------

def get_download_url():
    import platform
    arch = platform.machine()
    if "arm" in arch.lower() or "aarch64" in arch.lower():
        return "https://arm64.eooce.com/agent" if NEZHA_PORT else "https://arm64.eooce.com/v1"
    return "https://amd64.eooce.com/agent" if NEZHA_PORT else "https://amd64.eooce.com/v1"

async def download_file():
    if not (NEZHA_SERVER and NEZHA_KEY):
        return
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(get_download_url()) as resp:
                if resp.status == 200:
                    with open("npm", "wb") as f:
                        f.write(await resp.read())
                    os.chmod("npm", 0o755)
    except Exception as e:
        logger.error("Download failed: %s", e)

async def run_nezha():
    if not (NEZHA_SERVER and NEZHA_KEY):
        return
    await download_file()
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        if "./npm" in result.stdout and "[n]pm" in result.stdout:
            return
    except Exception:
        pass

    tls_ports = {"443", "8443", "2096", "2087", "2083", "2053"}
    if NEZHA_PORT:
        tls = "--tls" if NEZHA_PORT in tls_ports else ""
        cmd = (
            f"nohup ./npm -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} "
            f"{tls} --disable-auto-update --report-delay 4 --skip-conn --skip-procs "
            ">/dev/null 2>&1 &"
        )
    else:
        port = NEZHA_SERVER.split(":")[-1] if ":" in NEZHA_SERVER else ""
        config = f"""client_secret: {NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: {NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {'true' if port in tls_ports else 'false'}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""
        with open("config.yaml", "w", encoding="utf-8") as f:
            f.write(config)
        cmd = "nohup ./npm -c config.yaml >/dev/null 2>&1 &"

    subprocess.Popen(cmd, shell=True, executable="/bin/bash")

def cleanup_files():
    for file in ("npm", "config.yaml"):
        try:
            if os.path.exists(file):
                os.remove(file)
        except Exception:
            pass

async def main():
    load_settings()

    actual_port = PORT
    if not is_port_available(actual_port):
        new_port = find_available_port(actual_port + 1)
        if not new_port:
            raise RuntimeError("No available ports found")
        actual_port = new_port
        logger.warning("Port %s busy; using %s", PORT, actual_port)

    app = web.Application()
    app.router.add_get("/", http_handler)
    app.router.add_get(f"/{SUB_PATH}", http_handler)
    app.router.add_get(f"/{WSPATH}", websocket_handler)
    app.router.add_get("/api/settings", api_settings_get)
    app.router.add_post("/api/settings", api_settings_post)
    app.router.add_get("/api/configs", api_configs)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", actual_port)
    await site.start()

    logger.info("Server running on %s", actual_port)
    logger.info("Dashboard: http://0.0.0.0:%s/", actual_port)

    asyncio.create_task(run_nezha())
    try:
        await asyncio.Future()
    finally:
        await runner.cleanup()
        cleanup_files()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        cleanup_files()
        print("Server stopped")
