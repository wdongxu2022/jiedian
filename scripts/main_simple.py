#!/usr/bin/env python3
import os, re, json, base64, yaml

def pv(u, i):
    m=re.match(r'vless://([^@]+)@([^:]+):(\d+)\??(.*)',u)
    if not m:return None
    uid,srv,prt,q=m.groups()
    p=dict(re.findall(r'([^=&#]+)=([^&#]*)',q))
    n={"name":f"NODE-{i}", "type":"vless", "server":srv, "port":int(prt), "uuid":uid,
       "network":p.get('type','tcp'), "tls":p.get('security') in ('tls','reality')}
    if p.get('sni'):n["servername"]=p['sni']
    if p.get('fp'):n["client-fingerprint"]=p['fp']
    if p.get('flow'):n["flow"]=p['flow']
    if p.get('security')=='reality':
        n["reality-opts"]={"public-key":p.get('pbk','')}
        if p.get('sid'):n["reality-opts"]["short-id"]=p['sid']
    if n["network"]=="ws" and p.get('path'):
        n["ws-opts"]={"path":p['path']}
        if p.get('host'):n["ws-opts"]["headers"]={"Host":p['host']}
    return n

def pvm(u, i):
    try:
        b=u[8:]+'='*(-len(u[8:])%4)
        d=json.loads(base64.b64decode(b).decode())
        n={"name":f"NODE-{i}", "type":"vmess", "server":d.get('add',''),
           "port":int(d.get('port',0)), "uuid":d.get('id',''),
           "alterId":int(d.get('aid',0)), "cipher":d.get('scy','auto'),
           "network":d.get('net','tcp'), "tls":d.get('tls')=='tls'}
        if d.get('sni'):n["servername"]=d['sni']
        if d.get('fp'):n["client-fingerprint"]=d['fp']
        if n["network"]=="ws" and d.get('path'):
            n["ws-opts"]={"path":d['path']}
            if d.get('host'):n["ws-opts"]["headers"]={"Host":d['host']}
        return n
    except:return None

def pss(u, i):
    m=re.match(r'ss://([^@]+)@([^:]+):(\d+)\??(.*)',u)
    if not m:return None
    up,srv,prt,q=m.groups()
    dec=base64.b64decode(up+'='*(-len(up)%4)).decode(errors='ignore')
    meth,pwd=dec.split(':',1) if ':' in dec else ('unknown',dec)
    p=dict(re.findall(r'([^=&#]+)=([^&#]*)',q))
    n={"name":f"NODE-{i}", "type":"ss", "server":srv, "port":int(prt),
       "cipher":meth, "password":pwd, "udp":True}
    if p.get('plugin'):n["plugin"]=p['plugin']
    return n

def ptr(u, i):
    m=re.match(r'trojan://([^@]+)@([^:]+):(\d+)\??(.*)',u)
    if not m:return None
    pwd,srv,prt,q=m.groups()
    p=dict(re.findall(r'([^=&#]+)=([^&#]*)',q))
    n={"name":f"NODE-{i}", "type":"trojan", "server":srv, "port":int(prt),
       "password":pwd, "udp":True, "tls":True}
    if p.get('sni'):n["servername"]=p['sni']
    if p.get('fp'):n["client-fingerprint"]=p['fp']
    return n

def extract(text):
    nodes=set(re.findall(r'((?:vmess|vless|ss|trojan|hysteria2|hy2)://[^s"'\'']+)', text))
    for line in text.split('\n'):
        line=line.strip()
        if len(line)>100:
            try:
                nodes.update(extract(base64.b64decode(line).decode('utf-8',errors='ignore')))
            except:pass
    return nodes

def fetch():
    urls=["https://raw.githubusercontent.com/freefq/free/master/v2",
          "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
          "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
          "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"]
    all_nodes=set()
    for url in urls:
        try:
            r=__import__('requests').get(url,timeout=5,headers={"User-Agent":"Mozilla/5.0"})
            if r.status_code==200:
                all_nodes.update(extract(r.text))
        except:pass
    return list(all_nodes)

def main():
    os.makedirs("output",exist_ok=True)
    nodes=fetch()
    proxies=[]
    for i,n in enumerate(nodes):
        if n.startswith('vless://'):p=pv(n,i+1)
        elif n.startswith('vmess://'):p=pvm(n,i+1)
        elif n.startswith('ss://'):p=pss(n,i+1)
        elif n.startswith('trojan://'):p=ptr(n,i+1)
        else:continue
        if p:proxies.append(p)
    print(f"Parsed {len(proxies)} proxies")
    config={"mixed-port":7890,"allow-lan":True,"mode":"rule","log-level":"info",
        "proxies":proxies,
        "proxy-groups":[
            {"name":"PROXY","type":"select","proxies":["auto","fallback"]},
            {"name":"auto","type":"url-test","url":"https://www.gstatic.com/generate_204","interval":300,"proxies":[p["name"] for p in proxies]},
            {"name":"fallback","type":"fallback","url":"https://www.gstatic.com/generate_204","interval":300,"proxies":[p["name"] for p in proxies]},
        ],
        "rules":["DOMAIN,sni.macromedia.com,DIRECT","DOMAIN,classic.aco.rtmp.macromedia.com,DIRECT","GEOIP,cn,DIRECT","MATCH,PROXY"]}
    with open("output/clash.yaml","w",encoding="utf-8") as f:
        yaml.dump(config,f,allow_unicode=True,default_flow_style=False,sort_keys=False)
    with open("output/v2ray.txt","w",encoding="utf-8") as f:
        f.write('\n'.join(nodes))
    print("Done!")

if __name__=="__main__":
    main()