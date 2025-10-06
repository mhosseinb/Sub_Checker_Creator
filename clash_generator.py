import yaml
import json
import base64
import urllib.parse
from typing import List, Dict, Any

def _process_proxies(configs: List[str]) -> List[Dict[str, Any]]:
    """پردازش لیست کانفیگ‌ها و بازگرداندن لیست پروکسی‌های یکتا"""
    proxies = []
    seen_names = {}
    
    for idx, config in enumerate(configs, start=1):
        proxy = None
        original_name = None
        try:
            if config.startswith("vmess://"):
                encoded_part = config.split("://", 1)[1]
                missing_padding = len(encoded_part) % 4
                if missing_padding: 
                    encoded_part += '=' * (4 - missing_padding)
                decoded_json = base64.b64decode(encoded_part).decode('utf-8')
                vmess_config = json.loads(decoded_json)
                original_name = vmess_config.get('ps')
                server = vmess_config.get('add')
                port = vmess_config.get('port')
                if not server or not port:
                    raise ValueError("Missing server or port")
                proxy = {
                    "name": "", "type": "vmess", "server": server, "port": int(port),
                    "uuid": vmess_config.get('id'), "alterId": int(vmess_config.get('aid', 0)),
                    "cipher": vmess_config.get('scy', "auto"), "tls": vmess_config.get('tls') == 'tls'
                }
                if vmess_config.get('net'): proxy["network"] = vmess_config.get('net')
                if vmess_config.get('path'): proxy["ws-path"] = vmess_config.get('path')
                if vmess_config.get('host'): proxy["ws-headers"] = {"Host": vmess_config.get('host')}
                if vmess_config.get('sni'): proxy["servername"] = vmess_config.get('sni')
                    
            elif config.startswith("vless://"):
                parts = config.split("://", 1)[1]
                if "@" not in parts: raise ValueError("Invalid VLESS")
                user_info, server_info = parts.split("@", 1)
                if "#" in server_info:
                    server_address, remark = server_info.split("#", 1)
                    original_name = urllib.parse.unquote(remark)
                else:
                    server_address = server_info
                    original_name = None
                host, port = server_info.split(":", 1) if ":" in server_info else (server_info, "443")
                params = {}
                if "?" in user_info:
                    uuid_part, query = user_info.split("?", 1)
                    for param in query.split("&"):
                        if "=" in param:
                            k, v = param.split("=", 1)
                            params[k] = v
                    uuid = uuid_part
                else:
                    uuid = user_info
                proxy = {
                    "name": "", "type": "vless", "server": host, "port": int(port),
                    "uuid": uuid, "tls": params.get("security", "") == "tls"
                }
                if "type" in params: proxy["network"] = params["type"]
                if "path" in params: proxy["ws-path"] = params["path"]
                if "host" in params: proxy["ws-headers"] = {"Host": params["host"]}
                if "sni" in params: proxy["servername"] = params["sni"]
                    
            elif config.startswith("trojan://"):
                parts = config.split("://", 1)[1]
                if "@" not in parts: raise ValueError("Invalid Trojan")
                password, server_info = parts.split("@", 1)
                if "#" in server_info:
                    server_address, remark = server_info.split("#", 1)
                    original_name = urllib.parse.unquote(remark)
                else:
                    server_address = server_info
                    original_name = None
                host, port = server_address.split(":", 1)
                params = {}
                if "?" in password:
                    password, query = password.split("?", 1)
                    for param in query.split("&"):
                        if "=" in param:
                            k, v = param.split("=", 1)
                            params[k] = v
                proxy = {
                    "name": "", "type": "trojan", "server": host, "port": int(port),
                    "password": password, "tls": True
                }
                if "sni" in params: proxy["sni"] = params["sni"]
                    
            elif config.startswith("ss://"):
                parts = config.split("://", 1)[1]
                if "@" in parts:
                    user_info, server_info = parts.split("@", 1)
                    try:
                        decoded = base64.b64decode(user_info).decode('utf-8')
                        method, password = decoded.split(":", 1)
                    except:
                        method, password = user_info.split(":", 1)
                    if "#" in server_info:
                        server_address, remark = server_info.split("#", 1)
                        original_name = urllib.parse.unquote(remark)
                    else:
                        server_address = server_info
                        original_name = None
                    host, port = server_address.split(":", 1)
                else:
                    if "#" in parts:
                        encoded_part, remark = parts.split("#", 1)
                        original_name = urllib.parse.unquote(remark)
                        encoded_part = encoded_part
                    else:
                        encoded_part = parts
                        original_name = None
                    missing_padding = len(encoded_part) % 4
                    if missing_padding: encoded_part += '=' * (4 - missing_padding)
                    try:
                        decoded = base64.b64decode(encoded_part).decode('utf-8')
                        method_pass, server_port = decoded.split("@", 1)
                        method, password = method_pass.split(":", 1)
                        host, port = server_port.split(":", 1)
                    except:
                        continue
                proxy = {
                    "name": "", "type": "ss", "server": host, "port": int(port),
                    "cipher": method, "password": password
                }
            
            if proxy and "server" in proxy and "port" in proxy:
                base_name = (original_name.strip() if original_name and original_name.strip() else "Proxy")
                seen_names[base_name] = seen_names.get(base_name, 0) + 1
                count = seen_names[base_name]
                unique_name = base_name if count == 1 else f"{base_name} #{count}"
                proxy["name"] = unique_name
                proxies.append(proxy)
                
        except Exception as e:
            print(f"⚠️ خطا در پردازش کانفیگ #{idx}: {e}")
    
    return proxies

def generate_clash_configs(configs: List[str], output_general: str = "clash.yaml", output_meta: str = "clash_meta.yaml"):
    """
    تولید همزمان دو فایل کانفیگ:
    - output_general: برای Clash معمولی (با Rule-Set)
    - output_meta: برای Clash.Meta (با GEOIP/GEOSITE)
    """
    print("\n" + "="*60)
    print("🔄 در حال تولید همزمان دو کانفیگ Clash...")
    
    proxies = _process_proxies(configs)
    proxy_names = [p["name"] for p in proxies]
    print(f"✅ تعداد پروکسی‌های پردازش‌شده: {len(proxies)}")

    # ---------- 1. کانفیگ عمومی (Rule-Set) ----------
    general_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"]},
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": proxy_names},
            {"name": "DIRECT", "type": "select", "proxies": ["DIRECT"]},
            {"name": "REJECT", "type": "select", "proxies": ["REJECT"]}
        ],
        "rule-providers": {
            "ir": {"type": "http", "format": "yaml", "behavior": "domain", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.yaml", "path": "./ruleset/ir.yaml", "interval": 86400},
            "ads": {"type": "http", "format": "yaml", "behavior": "domain", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.yaml", "path": "./ruleset/ads.yaml", "interval": 86400},
            "malware": {"type": "http", "format": "yaml", "behavior": "domain", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.yaml", "path": "./ruleset/malware.yaml", "interval": 86400},
            "phishing": {"type": "http", "format": "yaml", "behavior": "domain", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.yaml", "path": "./ruleset/phishing.yaml", "interval": 86400},
            "cryptominers": {"type": "http", "format": "yaml", "behavior": "domain", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.yaml", "path": "./ruleset/cryptominers.yaml", "interval": 86400},
            "apps": {"type": "http", "format": "yaml", "behavior": "classical", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/apps.yaml", "path": "./ruleset/apps.yaml", "interval": 86400},
            "ircidr": {"type": "http", "format": "yaml", "behavior": "ipcidr", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.yaml", "path": "./ruleset/ircidr.yaml", "interval": 86400},
            "private": {"type": "http", "format": "yaml", "behavior": "ipcidr", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/private.yaml", "path": "./ruleset/private.yaml", "interval": 86400},
            "irasn": {"type": "http", "format": "yaml", "behavior": "classical", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.yaml", "path": "./ruleset/irasn.yaml", "interval": 86400}
        },
        "rules": [
            "RULE-SET,private,DIRECT,no-resolve",
            "RULE-SET,apps,DIRECT",
            "RULE-SET,ads,REJECT",
            "RULE-SET,malware,REJECT",
            "RULE-SET,phishing,REJECT",
            "RULE-SET,cryptominers,REJECT",
            "RULE-SET,ir,DIRECT",
            "RULE-SET,ircidr,DIRECT",
            "RULE-SET,irasn,DIRECT",
            "MATCH,PROXY"
        ]
    }

    # ---------- 2. کانفیگ Clash.Meta (GEOIP/GEOSITE) ----------
    meta_config_base = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"]},
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": proxy_names},
            {"name": "DIRECT", "type": "select", "proxies": ["DIRECT"]},
            {"name": "REJECT", "type": "select", "proxies": ["REJECT"]}
        ],
        "rules": [
            "GEOIP,private,DIRECT,no-resolve",
            "GEOSITE,category-ads-all,REJECT",
            "GEOSITE,malware,REJECT",
            "GEOSITE,phishing,REJECT",
            "GEOSITE,cryptominers,REJECT",
            "GEOIP,malware,REJECT",
            "GEOIP,phishing,REJECT",
            "GEOSITE,ir,DIRECT",
            "GEOIP,ir,DIRECT",
            "MATCH,PROXY"
        ]
    }
    geox_url = {
        "geoip": "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat",
        "geosite": "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat",
        "mmdb": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/geoip.metadb",
        "asn": "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/geolite2/GeoLite2-ASN.mmdb"
    }

    # ---------- ذخیره فایل‌ها ----------
    success = True

    # ذخیره کانفیگ عمومی
    try:
        with open(output_general, "w", encoding="utf-8") as f:
            yaml.dump(general_config, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
        print(f"✅ {output_general} → برای Clash معمولی (ClashA، Clash for Windows، ...)")
    except Exception as e:
        print(f"❌ خطا در ذخیره {output_general}: {e}")
        success = False

    # ذخیره کانفیگ Clash.Meta
    try:
        with open(output_meta, "w", encoding="utf-8") as f:
            yaml.dump({"geox-url": geox_url}, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
            f.write("\n")
            yaml.dump(meta_config_base, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
        print(f"✅ {output_meta} → فقط برای Clash.Meta (Clash Verge Rev، Clash Meta Desktop، ...)")
        print("\n💡 نکته: Clash.Meta در اولین اجرا فایل‌های geo را دانلود می‌کند.")
    except Exception as e:
        print(f"❌ خطا در ذخیره {output_meta}: {e}")
        success = False

    print("="*60)
    if success:
        print("🎉 هر دو کانفیگ با موفقیت تولید شدند!")
    else:
        print("⚠️ برخی فایل‌ها ذخیره نشدند. لطفاً خطاها را بررسی کنید.")
    return len(proxies)

# --- مثال استفاده ---
if __name__ == "__main__":
    sample_configs = [
        "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwMTIiLCJhaWQiOjAsIm5ldCI6IndzIiwicGF0aCI6Ii9wYXRoIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwicHMiOiJUZXN0IFZNZXNzIn0=",
        "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&path=/path#Test VLESS",
        "vless://12345678-1234-1234-1234-123456789012@example2.com:443?security=tls&type=ws&path=/path#Test VLESS"
    ]
    
    generate_clash_configs(
        configs=sample_configs,
        output_general="clash.yaml",
        output_meta="clash_meta.yaml"
    )
