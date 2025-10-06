import yaml
import json
import base64
import urllib.parse
from typing import List, Dict, Any

def generate_clash_config(configs: List[str], output_file: str = "clash.yaml"):
    """
    تبدیل کانفیگ‌های پروکسی به فرمت Clash.Meta با پشتیبانی از Rule Providers
    
    Args:
        configs: لیست کانفیگ‌های پروکسی
        output_file: مسیر فایل خروجی
    """
    print("\n" + "="*50)
    print("تولید کانفیگ Clash.Meta...")
    
    # ساختار پایه کانفیگ Clash.Meta
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": [],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"]
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": []
            },
            {
                "name": "DIRECT",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "REJECT",
                "type": "select",
                "proxies": ["REJECT"]
            }
        ],
        # Rule Providers برای ایران، تبلیغات، بدافزار و ...
        "rule-providers": {
            "ir": {
                "type": "http",
                "format": "yaml",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.yaml",
                "path": "./ruleset/ir.yaml",
                "interval": 86400
            },
            "ads": {
                "type": "http",
                "format": "yaml",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.yaml",
                "path": "./ruleset/ads.yaml",
                "interval": 86400
            },
            "malware": {
                "type": "http",
                "format": "yaml",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.yaml",
                "path": "./ruleset/malware.yaml",
                "interval": 86400
            },
            "phishing": {
                "type": "http",
                "format": "yaml",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.yaml",
                "path": "./ruleset/phishing.yaml",
                "interval": 86400
            },
            "cryptominers": {
                "type": "http",
                "format": "yaml",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.yaml",
                "path": "./ruleset/cryptominers.yaml",
                "interval": 86400
            },
            "apps": {
                "type": "http",
                "format": "yaml",
                "behavior": "classical",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/apps.yaml",
                "path": "./ruleset/apps.yaml",
                "interval": 86400
            },
            "ircidr": {
                "type": "http",
                "format": "yaml",
                "behavior": "ipcidr",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.yaml",
                "path": "./ruleset/ircidr.yaml",
                "interval": 86400
            },
            "private": {
                "type": "http",
                "format": "yaml",
                "behavior": "ipcidr",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/private.yaml",
                "path": "./ruleset/private.yaml",
                "interval": 86400
            },
            "irasn": {
                "type": "http",
                "format": "yaml",
                "behavior": "classical",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.yaml",
                "path": "./ruleset/irasn.yaml",
                "interval": 86400
            }
        },
        # قوانین جدید بر اساس Rule Providers
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
    
    # تبدیل کانفیگ‌ها به فرمت Clash
    proxy_names = []
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
                    raise ValueError("Missing server or port in VMess config")
                
                proxy = {
                    "name": "",
                    "type": "vmess",
                    "server": server,
                    "port": int(port),
                    "uuid": vmess_config.get('id'),
                    "alterId": int(vmess_config.get('aid', 0)),
                    "cipher": vmess_config.get('scy', "auto"),
                    "tls": vmess_config.get('tls') == 'tls',
                }
                
                if vmess_config.get('net'):
                    proxy["network"] = vmess_config.get('net')
                if vmess_config.get('path'):
                    proxy["ws-path"] = vmess_config.get('path')
                if vmess_config.get('host'):
                    proxy["ws-headers"] = {"Host": vmess_config.get('host')}
                if vmess_config.get('sni'):
                    proxy["servername"] = vmess_config.get('sni')
                    
            elif config.startswith("vless://"):
                parts = config.split("://", 1)[1]
                if "@" not in parts:
                    raise ValueError("Invalid VLESS format")
                user_info, server_info = parts.split("@", 1)
                
                if "#" in server_info:
                    server_address, remark = server_info.split("#", 1)
                    original_name = urllib.parse.unquote(remark)
                else:
                    server_address = server_info
                    original_name = None
                
                host, port = server_address.split(":", 1)
                
                params = {}
                if "?" in user_info:
                    uuid_part, query = user_info.split("?", 1)
                    for param in query.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            params[key] = value
                    uuid = uuid_part
                else:
                    uuid = user_info
                
                proxy = {
                    "name": "",
                    "type": "vless",
                    "server": host,
                    "port": int(port),
                    "uuid": uuid,
                    "tls": params.get("security", "") == "tls",
                }
                
                if "type" in params:
                    proxy["network"] = params.get("type")
                if "path" in params:
                    proxy["ws-path"] = params.get("path")
                if "host" in params:
                    proxy["ws-headers"] = {"Host": params.get("host")}
                if "sni" in params:
                    proxy["servername"] = params.get("sni")
                    
            elif config.startswith("trojan://"):
                parts = config.split("://", 1)[1]
                if "@" not in parts:
                    raise ValueError("Invalid Trojan format")
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
                            key, value = param.split("=", 1)
                            params[key] = value
                
                proxy = {
                    "name": "",
                    "type": "trojan",
                    "server": host,
                    "port": int(port),
                    "password": password,
                    "tls": True,
                }
                
                if "sni" in params:
                    proxy["sni"] = params.get("sni")
                    
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
                    if missing_padding: 
                        encoded_part += '=' * (4 - missing_padding)
                    
                    try:
                        decoded = base64.b64decode(encoded_part).decode('utf-8')
                        method_pass, server_port = decoded.split("@", 1)
                        method, password = method_pass.split(":", 1)
                        host, port = server_port.split(":", 1)
                    except Exception as e:
                        print(f"Error decoding SS config: {e}")
                        continue
                
                proxy = {
                    "name": "",
                    "type": "ss",
                    "server": host,
                    "port": int(port),
                    "cipher": method,
                    "password": password
                }
            
            # اگر پروکسی معتبر بود
            if proxy and "server" in proxy and "port" in proxy:
                if not original_name or original_name.strip() == "":
                    base_name = "Proxy"
                else:
                    base_name = original_name.strip()
                
                seen_names[base_name] = seen_names.get(base_name, 0) + 1
                count = seen_names[base_name]
                unique_name = base_name if count == 1 else f"{base_name} #{count}"
                
                proxy["name"] = unique_name
                clash_config["proxies"].append(proxy)
                proxy_names.append(unique_name)
                
        except Exception as e:
            print(f"Error processing config #{idx}: {e}")
    
    # به‌روزرسانی گروه‌های پروکسی
    for group in clash_config["proxy-groups"]:
        if group["name"] == "AUTO":
            group["proxies"] = proxy_names
        elif group["name"] == "PROXY":
            group["proxies"] = ["AUTO"] + proxy_names
    
    # ذخیره کانفیگ
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
        print(f"✅ کانفیگ Clash.Meta با {len(proxy_names)} پروکسی در '{output_file}' ذخیره شد.")
        print("💡 نکته: برای اولین بار، Clash.Meta ممکن است چند ثانیه طول بکشد تا Rule Providers را دانلود کند.")
    except Exception as e:
        print(f"❌ خطا در نوشتن فایل: {e}")
    
    print("="*50 + "\n")
    return len(proxy_names)

if __name__ == "__main__":
    sample_configs = [
        "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwMTIiLCJhaWQiOjAsIm5ldCI6IndzIiwicGF0aCI6Ii9wYXRoIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwicHMiOiJUZXN0IFZNZXNzIn0=",
        "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&path=/path#Test VLESS",
        "vless://12345678-1234-1234-1234-123456789012@example2.com:443?security=tls&type=ws&path=/path#Test VLESS",
    ]
    generate_clash_config(sample_configs, "clash_meta.yaml")
