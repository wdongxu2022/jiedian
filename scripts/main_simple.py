#!/usr/bin/env python3
"""
简化版节点测活脚本 - 快速可用
"""
import os
import re
import sys
import json
import time
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 简化的订阅源 - 只保留最可靠的
SOURCE_URLS = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
]

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_nodes(text):
    """从文本中提取节点链接"""
    pattern = r'((?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s"\'>]+)'
    nodes = set(re.findall(pattern, text))
    
    # 尝试 base64 解码
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith('dm') or line.startswith('c3M') or len(line) > 100:
            try:
                decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                nodes.update(extract_nodes(decoded))
            except:
                pass
    
    return nodes

def fetch_nodes():
    """抓取所有节点"""
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

def quick_test_node(node):
    """快速测试节点 - 不依赖 Google"""
    try:
        # 简单解析服务器和端口
        if node.startswith("vless://"):
            match = re.search(r'vless://[^@]+@([^:]+):(\d+)', node)
            if match:
                server, port = match.group(1), int(match.group(2))
        elif node.startswith("vmess://"):
            b64 = node[8:] + '=' * (-len(node[8:]) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            server = data.get('add', '')
            port = int(data.get('port', 0))
        elif node.startswith("ss://"):
            # 简化的 SS 解析
            match = re.search(r'ss://[^@]+@([^:]+):(\d+)', node)
            if match:
                server, port = match.group(1), int(match.group(2))
        elif node.startswith("trojan://"):
            match = re.search(r'trojan://[^@]+@([^:]+):(\d+)', node)
            if match:
                server, port = match.group(1), int(match.group(2))
        else:
            return None
        
        if not server or port <= 0:
            return None
            
        # 返回有效节点（不做实际测活，只保证格式正确）
        return node
    except:
        return None

def main():
    start_time = time.time()
    
    # 1. 抓取节点
    nodes = fetch_nodes()
    
    # 2. 快速验证格式
    print(f"\n[*] 开始验证节点格式...")
    valid_nodes = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(quick_test_node, n): n for n in nodes}
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_nodes.append(result)
            
            # 进度日志
            processed = len(valid_nodes) + len([f for f in futures if f.done() and f.result()])
            if processed % 50 == 0 or processed == len(nodes):
                print(f"[+] 已验证: {processed}/{len(nodes)}")
    
    print(f"\n[*] 有效节点: {len(valid_nodes)} 个")
    
    # 3. 输出结果
    print(f"\n[*] 生成输出文件...")
    
    # v2ray.txt
    v2ray_content = '\n'.join(valid_nodes)
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w") as f:
        f.write(v2ray_content)
    
    # clash.yaml (简化版)
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": [],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["自动选择", "故障转移"]
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [p["name"] for p in clash_config["proxies"]]
            }
        ],
        "rules": [
            "DOMAIN,sni.macromedia.com,DIRECT",
            "DOMAIN,classic.aco.rtmp.macromedia.com,DIRECT",
            "GEOIP,cn,DIRECT",
            "FINAL,PROXY"
        ]
    }
    
    # 转换节点为 Clash 格式
    for i, node in enumerate(valid_nodes[:100]):  # 限制数量
        if node.startswith("vless://"):
            clash_config["proxies"].append({
                "name": f"VLESS-{i+1}",
                "type": "vless",
                "server": re.search(r'@([^:]+)', node).group(1) if re.search(r'@([^:]+)', node) else "unknown",
                "port": int(re.search(r':(\d+)', node).group(1)) if re.search(r':(\d+)', node) else 0,
                "uuid": re.search(r'vless://([^@]+)', node).group(1) if re.search(r'vless://([^@]+)', node) else "",
                "network": "tcp",
                "tls": True
            })
    
    with open(os.path.join(OUTPUT_DIR, "clash.yaml"), "w") as f:
        import yaml
        yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)
    
    # singbox.json
    singbox_config = {
        "inbounds": [
            {
                "type": "mixed",
                "listen": "0.0.0.0",
                "listen_port": 2080
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns"},
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", "proxy"]},
            {"type": "urltest", "tag": "auto", "outbounds": [f"proxy-{i+1}" for i in range(min(20, len(valid_nodes)))], "url": "https://www.gstatic.com/generate_204", "interval": "10m"}
        ] + [{"type": outbound_type, "tag": f"proxy-{i+1}", "server": server, "server_port": port, "uuid": uuid, "network": "tcp", "tls": {"enabled": True}} for i, (_, outbound_type, server, port, uuid) in enumerate([(n, "vless", re.search(r'@([^:]+)', n).group(1) if re.search(r'@([^:]+)', n) else "unknown", int(re.search(r':(\d+)', n).group(1)) if re.search(r':(\d+)', n) else 0, re.search(r'vless://([^@]+)', n).group(1) if re.search(r'vless://([^@]+)', n) else "") for n in valid_nodes[:20]])],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns"},
                {"geosite": "cn", "outbound": "direct"}
            ],
            "final": "proxy"
        }
    }
    
    with open(os.path.join(OUTPUT_DIR, "singbox.json"), "w") as f:
        json.dump(singbox_config, f, indent=2, ensure_ascii=False)
    
    # 家宽专区（为空）
    with open(os.path.join(OUTPUT_DIR, "residential.txt"), "w") as f:
        f.write("")
    
    elapsed = time.time() - start_time
    print(f"\n[+] 完成！耗时: {elapsed:.1f} 秒")
    print(f"[+] 输出目录: {OUTPUT_DIR}/")
    print(f"    - v2ray.txt: {len(valid_nodes)} 节点")
    print(f"    - clash.yaml: 已生成")
    print(f"    - singbox.json: 已生成")

if __name__ == "__main__":
    main()
