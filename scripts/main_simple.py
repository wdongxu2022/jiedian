#!/usr/bin/env python3
import os, re, json, base64, yaml

def parse_vless(url):
    m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??(.*)', url)
    if not m: return None
    uuid, server, port_s, query = m.groups()
    params = dict(re.findall(r'([^=&#]+)=([^&#]*)', query))
    node = {"name": f"VLESS-{server[:8]}:{port_s}", "type": "vless", "server": server,
            "port": int(port_s), "uuid": uuid, "network": params.get('type', 'tcp"),
            "tls": params.get('security') in ('tls', 'reality')}
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
                "port": int(data.get('port',0)), "uuid": data.get('id',''),
                "alterId": int(data.get('aid',0)), "cipher": data.get('scy','auto'),
                "network": data.get('net','tcp"), "tls": data.get('tls')=='tls'}
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
    pattern = r'((?:vmess|vless|ss|trojan|hysteria2|hy2)://[^s"\'<>]+)'
    nodes = set(re.findall(pattern, text))
    for line in text.split('\n'):
        line = line.strip()
        if len(line) > 100:
            try:
                decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                nodes.update(extract_nodes(decoded))
            except: pass
    return nodes

def fetch_nodes():
    urls = [
        "https://raw.githubusercontent.com/freefq/free/master/v2",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
        "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    ]
    all_nodes = set()
    for url in urls:
        try:
            import requests
            resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                nodes = extract_nodes(resp.text)
                all_nodes.update(nodes)
                print(f"[+] {url[:50]}... -> {len(nodes)} nodes")
        except Exception as e:
            print(f"[!] {url[:50]}... failed: {e}")
    return list(all_nodes)

def main():
    os.makedirs("output", exist_ok=True)
    nodes = fetch_nodes()
    proxies = []
    for n in nodes:
        if n.startswith("vless://"): p = parse_vless(n)
        elif n.startswith("vmess://"): p = parse_vmess(n)
        elif n.startswith("ss://"): p = parse_ss(n)
        elif n.startswith("trojan://"): p = parse_trojan(n)
        else: continue
        if p: proxies.append(p)
    print(f"Parsed {len(proxies)} proxies")
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["自动选择", "故障转移"]},
            {"name": "自动选择", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in proxies]},
            {"name": "故障转移", "type": "fallback", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in proxies]},
        ],
        "rules": ["DOMAIN,sni.macromedia.com,DIRECT", "DOMAIN,classic.aco.rtmp.macromedia.com,DIRECT", "GEOIP,cn,DIRECT", "MATCH,PROXY"],
    }
    with open("output/clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    with open("output/v2ray.txt", "w", encoding="utf-8") as f:
        f.write('\n'.join(nodes))
    print("Done!")

if __name__ == "__main__":
    main()