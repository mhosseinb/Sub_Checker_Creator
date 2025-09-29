import yaml
import json
import base64
import urllib.parse
import re
from typing import List, Dict, Any

def generate_clash_config(configs: List[str], output_file: str = "clash.yaml"):
    """
    تبدیل کانفیگ‌های پروکسی به فرمت Clash و ذخیره در فایل
    
    Args:
        configs: لیست کانفیگ‌های پروکسی
        output_file: مسیر فایل خروجی
    """
    print("\n" + "="*50)
    print("تولید کانفیگ Clash...")
    
    # ساختار پایه کانفیگ Clash
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
                "name": "🚀 Proxy",
                "type": "select",
                "proxies": ["♻️ Auto"]
            },
            {
                "name": "♻️ Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": []
            },
            {
                "name": "🌍 Global Media",
                "type": "select",
                "proxies": ["🚀 Proxy", "♻️ Auto", "🎯 Direct"]
            },
            {
                "name": "🎯 Direct",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "🛑 Ad Block",
                "type": "select",
                "proxies": ["REJECT", "DIRECT"]
            },
            {
                "name": "🐟 Fallback",
                "type": "select",
                "proxies": ["🚀 Proxy", "🎯 Direct"]
            }
        ],
        "rules": [
            "DOMAIN-KEYWORD,adservice,🛑 Ad Block",
            "DOMAIN-SUFFIX,googlesyndication.com,🛑 Ad Block",
            "DOMAIN-SUFFIX,netflix.com,🌍 Global Media",
            "DOMAIN-SUFFIX,nflxvideo.net,🌍 Global Media",
            "DOMAIN-SUFFIX,disneyplus.com,🌍 Global Media",
            "DOMAIN-KEYWORD,youtube,🌍 Global Media",
            "DOMAIN-SUFFIX,t.me,🚀 Proxy",
            "DOMAIN-SUFFIX,telegram.org,🚀 Proxy",
            "DOMAIN-SUFFIX,openai.com,🚀 Proxy",
            "DOMAIN-SUFFIX,lan,🎯 Direct",
            "DOMAIN-SUFFIX,local,🎯 Direct",
            "IP-CIDR,127.0.0.0/8,🎯 Direct,no-resolve",
            "IP-CIDR,192.168.0.0/16,🎯 Direct,no-resolve",
            "IP-CIDR,10.0.0.0/8,🎯 Direct,no-resolve",
            "IP-CIDR,172.16.0.0/12,🎯 Direct,no-resolve",
            "GEOIP,IR,🎯 Direct",
            "MATCH,🐟 Fallback"
        ]
    }
    
    # تبدیل کانفیگ‌ها به فرمت Clash
    proxy_names = []
    for config in configs:
        proxy = None
        try:
            if config.startswith("vmess://"):
                # پردازش کانفیگ vmess
                encoded_part = config.split("://", 1)[1]
                missing_padding = len(encoded_part) % 4
                if missing_padding: 
                    encoded_part += '=' * (4 - missing_padding)
                decoded_json = base64.b64decode(encoded_part).decode('utf-8')
                vmess_config = json.loads(decoded_json)
                
                proxy = {
                    "name": vmess_config.get('ps', f"vmess-{len(proxy_names)}"),
                    "type": "vmess",
                    "server": vmess_config.get('add'),
                    "port": int(vmess_config.get('port')),
                    "uuid": vmess_config.get('id'),
                    "alterId": int(vmess_config.get('aid', 0)),
                    "cipher": vmess_config.get('scy', "auto"),
                    "tls": vmess_config.get('tls') == 'tls',
                }
                
                # اضافه کردن تنظیمات اختیاری
                if vmess_config.get('net'):
                    proxy["network"] = vmess_config.get('net')
                if vmess_config.get('path'):
                    proxy["ws-path"] = vmess_config.get('path')
                if vmess_config.get('host'):
                    proxy["ws-headers"] = {"Host": vmess_config.get('host')}
                if vmess_config.get('sni'):
                    proxy["servername"] = vmess_config.get('sni')
                    
            elif config.startswith("vless://"):
                # پردازش کانفیگ vless
                parts = config.split("://", 1)[1]
                user_info, server_info = parts.split("@", 1)
                
                # جدا کردن آدرس سرور و پورت
                if "#" in server_info:
                    server_address, remark = server_info.split("#", 1)
                    remark = urllib.parse.unquote(remark)
                else:
                    server_address = server_info
                    remark = f"vless-{len(proxy_names)}"
                
                host, port = server_address.split(":", 1)
                
                # پارامترهای اضافی
                params = {}
                if "?" in user_info:
                    uuid, query = user_info.split("?", 1)
                    for param in query.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            params[key] = value
                else:
                    uuid = user_info
                
                proxy = {
                    "name": remark,
                    "type": "vless",
                    "server": host,
                    "port": int(port),
                    "uuid": uuid,
                    "tls": params.get("security", "") == "tls",
                }
                
                # اضافه کردن تنظیمات اختیاری
                if "type" in params:
                    proxy["network"] = params.get("type")
                if "path" in params:
                    proxy["ws-path"] = params.get("path")
                if "host" in params:
                    proxy["ws-headers"] = {"Host": params.get("host")}
                if "sni" in params:
                    proxy["servername"] = params.get("sni")
                    
            elif config.startswith("trojan://"):
                # پردازش کانفیگ trojan
                parts = config.split("://", 1)[1]
                password, server_info = parts.split("@", 1)
                
                # جدا کردن آدرس سرور و پورت
                if "#" in server_info:
                    server_address, remark = server_info.split("#", 1)
                    remark = urllib.parse.unquote(remark)
                else:
                    server_address = server_info
                    remark = f"trojan-{len(proxy_names)}"
                
                host, port = server_address.split(":", 1)
                
                # پارامترهای اضافی
                params = {}
                if "?" in password:
                    password, query = password.split("?", 1)
                    for param in query.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            params[key] = value
                
                proxy = {
                    "name": remark,
                    "type": "trojan",
                    "server": host,
                    "port": int(port),
                    "password": password,
                    "tls": True,
                }
                
                # اضافه کردن تنظیمات اختیاری
                if "sni" in params:
                    proxy["sni"] = params.get("sni")
                    
            elif config.startswith("ss://"):
                # پردازش کانفیگ shadowsocks
                parts = config.split("://", 1)[1]
                
                if "@" in parts:
                    # فرمت جدید: ss://BASE64(method:password)@server:port#tag
                    user_info, server_info = parts.split("@", 1)
                    try:
                        decoded = base64.b64decode(user_info).decode('utf-8')
                        method, password = decoded.split(":", 1)
                    except:
                        method, password = user_info.split(":", 1)
                    
                    if "#" in server_info:
                        server_address, remark = server_info.split("#", 1)
                        remark = urllib.parse.unquote(remark)
                    else:
                        server_address = server_info
                        remark = f"ss-{len(proxy_names)}"
                    
                    host, port = server_address.split(":", 1)
                else:
                    # فرمت قدیمی: ss://BASE64(method:password@server:port)#tag
                    if "#" in parts:
                        encoded_part, remark = parts.split("#", 1)
                        remark = urllib.parse.unquote(remark)
                    else:
                        encoded_part = parts
                        remark = f"ss-{len(proxy_names)}"
                    
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
                    "name": remark,
                    "type": "ss",
                    "server": host,
                    "port": int(port),
                    "cipher": method,
                    "password": password
                }
            
            # اضافه کردن پروکسی به لیست اگر معتبر باشد
            if proxy and "server" in proxy and "port" in proxy:
                clash_config["proxies"].append(proxy)
                proxy_names.append(proxy["name"])
        except Exception as e:
            print(f"Error processing config for Clash: {e}")
    
    # اضافه کردن نام‌های پروکسی به گروه‌ها
    for group in clash_config["proxy-groups"]:
        if group["name"] == "♻️ Auto":
            group["proxies"] = proxy_names
        elif group["name"] == "🚀 Proxy":
            group["proxies"] = ["♻️ Auto"] + proxy_names
    
    # ذخیره کانفیگ Clash
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)
        print(f"کانفیگ Clash با {len(proxy_names)} پروکسی در فایل '{output_file}' ذخیره شد.")
    except Exception as e:
        print(f"!!! خطا در نوشتن فایل کانفیگ Clash: {e}")
    
    print("="*50 + "\n")
    return len(proxy_names)

if __name__ == "__main__":
    # تست تابع با یک کانفیگ نمونه
    sample_configs = [
        "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwMTIiLCJhaWQiOjAsIm5ldCI6IndzIiwicGF0aCI6Ii9wYXRoIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwicHMiOiJUZXN0IFZNZXNzIn0=",
        "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=tls&type=ws&path=/path#Test VLESS"
    ]
    generate_clash_config(sample_configs, "test_clash.yaml")