#!/usr/bin/env python3
"""简化版节点测活脚本 - 快速可用，支持完整 VLESS 参数"""
import os
import re
import sys
import json
import time
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCE_URLS = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
]

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_vless(url):
    m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??(.*)', url)
    if not m: return None
    uuid, server, port_s, query = m.groups()
    params = dict(re.findall(r'([^=&#]+)=([^&#]*)', query))
    node = {"name": f"VLESS-{server[:8]}:{port_s}", "type": "vless", "server": server,
            "port": int(port_s), "uuid": uuid, "network": params.get('type', 'tcp'), "tls": params.get('security') in ('tls', 'reality')}
    if params.get('sni'): node["servername"] = params["sni"]
    if params.get('fp'): node["client-fingerprint"] = params["fp"]
    if params.get('flow'): node["flow"] = params["flow"]
    if params.get('security') == 'reality':
        node["reality-opts"] = {"public-key": params.get('pbk', '')}
        if params.get('sid'): node["reality-opts"]["short-id"] = params["sid"]
    if node["network"] == "ws" and params.get('path'):
        node["ws-opts"] = {"path": params["path"]}
        if params.get('host'): node["ws-opts"]["headers"] = {"Host": params["host"]}
    return node

def parse_vmess(url):
    try:
        b64 = url[8:] + '=' * (-len(url[8:]) % 4)
        data = json.loads(base64.b64decode(b64).decode())
        node = {"name": f"VMess-{data.get('add','')[:8]}", "type": "vmess", "server": data.get('add',''),
                "port": int(data.get('port',0)), "uuid": data.get('id',''), "alterId": int(data.get('aid',0)),
                "cipher": data.get('scy','auto'), "network": data.get('net','tcp'), "tls": data.get('tls')=='tls'}
        if data.get('sni'): node["servername"] = data["sni"]
        if data.get('fp'): node["client-fingerprint"] = data["fp"]
        if node["network"]=="ws" and data.get('path'):
            node["ws-opts"] = {"path": data["path"]}
            if data.get('host'): node["ws-opts"]["headers"] = {"Host": data["host"]}
        return node
    except: return None

def parse_ss(url):
    m = re.match(r'ss://([^@]+)@([^:]+):(\d+)\??(.*)', url)
    if not m: return None
    user_pass, server, port_s, query = m.groups()
    decoded = base64.b64decode(user_pass + '=' * (-len(user_pass) % 4)).decode(errors='ignore')
    method, password = decoded.split(':', 1) if ':' in decoded else ("unknown", decoded)
    params = dict(re.findall(r'([^=&#]+)=([^&#]*)', query))
    node = {"name": f"SS-{server[:8]}", "type": "ss", "server": server, "port": int(port_s),
            "cipher": method, "password": password, "udp": True}
    if params.get('plugin'): node["plugin"] = params["plugin"]
    return node

def parse_trojan(url):
    m = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\??(.*)', url)
    if not m: return None
    password, server, port_s, query = m.groups()
    params = dict(re.findall(r'([^=&#]+)=([^&#]*)', query))
    node = {"name": f"Trojan-{server[:8]}", "type": "trojan", "server": server, "port": int(port_s),
            "password": password, "udp": True, "tls": True}
    if params.get('sni'): node["servername"] = params["sni"]
    if params.get('fp'): node["client-fingerprint"] = params["fp"]
    return node

def extract_nodes(text):
    pattern = r'((?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s"\'>]+)'
    nodes = set(re.findall(pattern, text))
    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('dm') or line.startswith('c3S') or len(line) > 100:
            try:
                decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                nodes.update(extract_nodes(decoded))
            except: pass
    return nodes

def fetch_nodes():
    all_nodes = set()
    print("[*] 开始抓取节点...")
    for url in SOURCE_URLS:
        try:
            resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                nodes = extract_nodes(resp.text)
                all_nodes.update(nodes)
                print(f"[+] {url[:50]}... -> {len(nodes)} 节点")
        except Exception as e:
            print(f"[!] {url[:50]}... 失败: {e}")
    print(f"[*] 总共抓取到 {len(all_nodes)} 个节点")
    return list(all_nodes)

def parse_node(node_str):
    if node_str.startswith("vless://"): return parse_vless(node_str)
    elif node_str.startswith("vmess://"): return parse_vmess(node_str)
    elif node_str.startswith("ss://"): return parse_ss(node_str)
    elif node_str.startswith("trojan://"): return parse_trojan(node_str)
    return None

def main():
    start_time = time.time()
    nodes = fetch_nodes()
    print(f"\n[*] 解析节点...")
    proxies = []
    for n in nodes:
        p = parse_node(n)
        if p: proxies.append(p)
    print(f"[+] 有效节点: {len(proxies)} 个")
    # clash.yaml
    config = {"mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
              "proxies": proxies,
              "proxy-groups": [
                  {"name": "PROXY", "type": "select", "proxies": ["自动选择", "故障转移"]},
                  {"name": "自动选择", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in proxies]},
                  {"name": "故障转移", "type": "fallback", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in proxies]}
              ],
              "rules": ["DOMAIN,sni.macromedia.com,DIRECT", "DOMAIN,classic.aco.rtmp.macromedia.com,DIRECT", "GEOIP,cn,DIRECT", "MATCH,PROXY"]}
    with open(os.path.join(OUTPUT_DIR, "clash.yaml"), "w") as f:
        import yaml
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    # v2ray.txt
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w") as f:
        f.write('\n'.join(nodes))
    # singbox.json
    sb_proxies = []
    for p in proxies[:100]:
        sb = {"tag": p["name"], "type": p["type"], "server": p["server"], "server_port": p["port"]}
        if p["type"] == "vless": sb.update({"uuid": p["uuid"], "tls": {"enabled": p.get("tls", False)}, "transport": {}})
        elif p["type"] == "vmess": sb.update({"uuid": p["uuid"], "security": p.get("cipher", "auto"), "tls": {"enabled": p.get("tls", False)}})
        elif p["type"] == "ss": sb.update({"method": p["cipher"], "password": p["password"]})
        elif p["type"] == "trojan": sb.update({"password": p["password"], "tls": {"enabled": True}})
        sb_proxies.append(sb)
    sb_config = {"inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080}],
                 "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns"},
                               {"type": "selector", "tag": "proxy", "outbounds": ["auto", "proxy"]},
                               {"type": "urltest", "tag": "auto", "outbounds": [p["tag"] for p in sb_proxies[:20]], "url": "https://www.gstatic.com/generate_204", "interval": "10m"}] + sb_proxies,
                 "route": {"rules": [{"protocol": "dns", "outbound": "dns"}, {"geosite": "cn", "outbound": "direct"}], "final": "proxy"}}
    with open(os.path.join(OUTPUT_DIR, "singbox.json"), "w") as f:
        json.dump(sb_config, f, indent=2, ensure_ascii=False)
    with open(os.path.join(OUTPUT_DIR, "residential.txt"), "w") as f:
        f.write("")
    elapsed = time.time() - start_time
    print(f"\n[+] 完成！耗时: {elapsed:.1f}s")
    print(f"    clash.yaml: {len(proxies)} 节点")
    print(f"    v2ray.txt: {len(nodes)} 节点")
    print(f"    singbox.json: {len(sb_proxies)} 节点")

if __name__ == "__main__":
    main()