import pyshark
import requests
import ipaddress
import sys
import threading
import time
import itertools
from tabulate import tabulate

if sys.stdout.isatty():
    R, G, C, W, Y, M, B = '\033[31m', '\033[32m', '\033[36m', '\033[0m', '\033[33m', '\033[35m', '\033[34m'
else:
    R = G = C = W = Y = M = B = ''

BANNER = rf"""{C}
=========================================================================

██╗██████╗ ██╗███████╗                                                      
██║██╔══██╗██║██╔════╝                                                      
██║██████╔╝██║███████╗                                                      
██║██╔══██╗██║╚════██║                                                      
██║██║  ██║██║███████║                                                      
╚═╝╚═╝  ╚═╝╚═╝╚══════╝                                                      
                                                                            
 ██████╗ █████╗ ███╗   ███╗ ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗
██╔════╝██╔══██╗████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝
██║     ███████║██╔████╔██║██║   ██║██████╔╝███████║██║     ██║     █████╗  
██║     ██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██║     ██║     ██╔══╝  
╚██████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝

{G} > Iris CamOracle:
{G} > >>> Passive Network Traffic Analyzer & IoT Vulnerability Profiler
{Y} > Author:{W} Peter Layetta
{Y} > Version:{W} 2.0.1
{C}======================================================================{W}
"""

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or 
                ip.is_loopback or 
                ip.is_multicast or 
                ip.is_link_local or 
                ip.is_reserved)
    except ValueError:
        return True

GEO_CACHE = {}
THREAT_CACHE = {}

def check_threat_intel(ip):
    if is_private_ip(ip): return "✅ Local IP"
    
    # cache to avoid limit API requests
    if ip in THREAT_CACHE: return THREAT_CACHE[ip]
    
    try:
        # Query ThreatFox by Abuse.ch
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ip}
        
        #POST request required by ThreatFox
        response = requests.post(url, json=payload, timeout=5).json()
        
        if response.get("query_status") == "ok":
            malware = response["data"][0].get("malware_printable", "Unknown Botnet/Malware")
            confidence = response["data"][0].get("confidence_level", 100)
            THREAT_CACHE[ip] = f"🚨 MALICIOUS ({malware} - {confidence}%)"
        else:
            THREAT_CACHE[ip] = "✅ Clean"
            
        return THREAT_CACHE[ip]
    except Exception as e:
        return "⚠️ Check Failed"
    
SHODAN_CACHE = {}

def check_shodan_osint(ip):
    if is_private_ip(ip): return "✅ Local Network"
    if ip in SHODAN_CACHE: return SHODAN_CACHE[ip]
    
    try:
        response = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            vulns = len(data.get("vulns", []))
            tags = ", ".join(data.get("tags", []))
            result = []
            if vulns > 0:
                result.append(f"⚠️ {vulns} Known Vulns")
            if tags:
                result.append(f"Tags: {tags}")
                
            if not result:
                SHODAN_CACHE[ip] = "✅ Clean (No CVEs/Tags)"
            else:
                SHODAN_CACHE[ip] = " | ".join(result)
        else:
            SHODAN_CACHE[ip] = "✅ Clean (Unlisted)"
            
        return SHODAN_CACHE[ip]
    except Exception as e:
        return "⚠️ Check Failed"

def get_geolocation(ip):
    if is_private_ip(ip): return "Local Network", "Local Network"
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,as", timeout=5).json()
        if response.get("status") == "success": 
            GEO_CACHE[ip] = (response.get("country", "Unknown"), response.get("as", "Unknown"))
            return GEO_CACHE[ip]
    except: pass
    return "Unknown", "Unknown"

# List for common RTP Payload types
RTP_PAYLOAD_MAP = {
    '0': 'PCMU (Audio)', '8': 'PCMA (Audio)', '26': 'JPEG (Video)', '33': 'MP2T (Video)', '34': 'H.263 (Video)'
}

# List for mapping Cipher Suites hex to their String Names (From Broadcom Symantec SSL)
CIPHER_MAP = {
    '0x0001': ('TLS_RSA_WITH_NULL_MD5', '❌ Insecure'),
    '0x0002': ('TLS_RSA_WITH_NULL_SHA', '❌ Insecure'),
    '0x0003': ('TLS_RSA_EXPORT_WITH_RC4_40_MD5', '❌ Insecure'),
    '0x0004': ('TLS_RSA_WITH_RC4_128_MD5', '❌ Insecure'),
    '0x0005': ('TLS_RSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x0006': ('TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', '❌ Insecure'),
    '0x0007': ('TLS_RSA_WITH_IDEA_CBC_SHA', '⚠️ Weak'),
    '0x0008': ('TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x0009': ('TLS_RSA_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x000a': ('TLS_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x000b': ('TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x000c': ('TLS_DH_DSS_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x000d': ('TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x000e': ('TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x000f': ('TLS_DH_RSA_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x0010': ('TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0011': ('TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x0012': ('TLS_DHE_DSS_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x0013': ('TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0014': ('TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x0015': ('TLS_DHE_RSA_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x0016': ('TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0017': ('TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5', '❌ Insecure'),
    '0x0018': ('TLS_DH_Anon_WITH_RC4_128_MD5', '❌ Insecure'),
    '0x0019': ('TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA', '❌ Insecure'),
    '0x001a': ('TLS_DH_Anon_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x001b': ('TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x001c': ('SSL_FORTEZZA_KEA_WITH_NULL_SHA', '❌ Insecure'),
    '0x001d': ('SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA', '⚠️ Weak'),
    '0x001e': ('TLS_KRB5_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x001f': ('TLS_KRB5_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0020': ('TLS_KRB5_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x0021': ('TLS_KRB5_WITH_IDEA_CBC_SHA', '⚠️ Weak'),
    '0x0022': ('TLS_KRB5_WITH_DES_CBC_MD5', '❌ Insecure'),
    '0x0023': ('TLS_KRB5_WITH_3DES_EDE_CBC_MD5', '❌ Insecure'),
    '0x0024': ('TLS_KRB5_WITH_RC4_128_MD5', '❌ Insecure'),
    '0x0025': ('TLS_KRB5_WITH_IDEA_CBC_MD5', '❌ Insecure'),
    '0x0026': ('TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', '❌ Insecure'),
    '0x0027': ('TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', '❌ Insecure'),
    '0x0028': ('TLS_KRB5_EXPORT_WITH_RC4_40_SHA', '❌ Insecure'),
    '0x0029': ('TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', '❌ Insecure'),
    '0x002a': ('TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', '❌ Insecure'),
    '0x002b': ('TLS_KRB5_EXPORT_WITH_RC4_40_MD5', '❌ Insecure'),
    '0x002c': ('TLS_PSK_WITH_NULL_SHA', '❌ Insecure'),
    '0x002d': ('TLS_DHE_PSK_WITH_NULL_SHA', '❌ Insecure'),
    '0x002e': ('TLS_RSA_PSK_WITH_NULL_SHA', '❌ Insecure'),
    '0x002f': ('TLS_RSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0x0030': ('TLS_DH_DSS_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0x0031': ('TLS_DH_RSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0x0032': ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0x0033': ('TLS_DHE_RSA_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0x0034': ('TLS_DH_Anon_WITH_AES_128_CBC_SHA', '❌ Insecure'),
    '0x0035': ('TLS_RSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0x0036': ('TLS_DH_DSS_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0x0037': ('TLS_DH_RSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0x0038': ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0x0039': ('TLS_DHE_RSA_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0x003a': ('TLS_DH_Anon_WITH_AES_256_CBC_SHA', '❌ Insecure'),
    '0x003b': ('TLS_RSA_WITH_NULL_SHA256', '❌ Insecure'),
    '0x003c': ('TLS_RSA_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0x003d': ('TLS_RSA_WITH_AES_256_CBC_SHA256', '⚠️ Weak'),
    '0x003e': ('TLS_DH_DSS_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0x003f': ('TLS_DH_RSA_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0x0040': ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0x0041': ('TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', '⚠️ Weak'),
    '0x0042': ('TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', '⚠️ Weak'),
    '0x0043': ('TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', '⚠️ Weak'),
    '0x0044': ('TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', '✅ Adequate'),
    '0x0045': ('TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', '✅ Adequate'),
    '0x0046': ('TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA', '❌ Insecure'),
    '0x0047': ('TLS_ECDH_ECDSA_WITH_NULL_SHA', '❌ Insecure'),
    '0x0048': ('TLS_ECDH_ECDSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x0049': ('TLS_ECDH_ECDSA_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x004a': ('TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x004b': ('TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0x004c': ('TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0x0060': ('TLS_RSA_EXPORT1024_WITH_RC4_56_MD5', '❌ Insecure'),
    '0x0061': ('TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5', '❌ Insecure'),
    '0x0062': ('TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x0063': ('TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0x0064': ('TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', '❌ Insecure'),
    '0x0065': ('TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA', '❌ Insecure'),
    '0x0066': ('TLS_DHE_DSS_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x0067': ('TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0x0068': ('TLS_DH_DSS_WITH_AES_256_CBC_SHA256', '⚠️ Weak'),
    '0x0069': ('TLS_DH_RSA_WITH_AES_256_CBC_SHA256', '⚠️ Weak'),
    '0x006a': ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', '✅ Adequate'),
    '0x006b': ('TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', '✅ Adequate'),
    '0x006c': ('TLS_DH_Anon_WITH_AES_128_CBC_SHA256', '❌ Insecure'),
    '0x006d': ('TLS_DH_Anon_WITH_AES_256_CBC_SHA256', '❌ Insecure'),
    '0x0080': ('TLS_GOSTR341094_WITH_28147_CNT_IMIT', '❌ Insecure'),
    '0x0081': ('TLS_GOSTR341001_WITH_28147_CNT_IMIT', '❌ Insecure'),
    '0x0082': ('TLS_GOSTR341094_WITH_NULL_GOSTR3411', '❌ Insecure'),
    '0x0083': ('TLS_GOSTR341001_WITH_NULL_GOSTR3411', '❌ Insecure'),
    '0x0084': ('TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', '⚠️ Weak'),
    '0x0085': ('TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', '⚠️ Weak'),
    '0x0086': ('TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', '⚠️ Weak'),
    '0x0087': ('TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', '✅ Adequate'),
    '0x0088': ('TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', '✅ Adequate'),
    '0x0089': ('TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA', '❌ Insecure'),
    '0x008a': ('TLS_PSK_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x008b': ('TLS_PSK_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x008c': ('TLS_PSK_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0x008d': ('TLS_PSK_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0x008e': ('TLS_DHE_PSK_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x008f': ('TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0090': ('TLS_DHE_PSK_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0x0091': ('TLS_DHE_PSK_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0x0092': ('TLS_RSA_PSK_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0x0093': ('TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0x0094': ('TLS_RSA_PSK_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0x0095': ('TLS_RSA_PSK_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0x0096': ('TLS_RSA_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x0097': ('TLS_DH_DSS_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x0098': ('TLS_DH_RSA_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x0099': ('TLS_DHE_DSS_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x009a': ('TLS_DHE_RSA_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x009b': ('TLS_DH_Anon_WITH_SEED_CBC_SHA', '❌ Insecure'),
    '0x009c': ('TLS_RSA_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0x009d': ('TLS_RSA_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0x009e': ('TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0x009f': ('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0x00a0': ('TLS_DH_RSA_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0x00a1': ('TLS_DH_RSA_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0x00a2': ('TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', '✅ Adequate'),
    '0x00a3': ('TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', '✅ Adequate'),
    '0x00a4': ('TLS_DH_DSS_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0x00a5': ('TLS_DH_DSS_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0x00a6': ('TLS_DH_Anon_WITH_AES_128_GCM_SHA256', '❌ Insecure'),
    '0x00a7': ('TLS_DH_Anon_WITH_AES_256_GCM_SHA384', '❌ Insecure'),
    '0x00a8': ('TLS_PSK_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0x00a9': ('TLS_PSK_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0x00aa': ('TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0x00ab': ('TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0x00ac': ('TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0x00ad': ('TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0x00ae': ('TLS_PSK_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0x00af': ('TLS_PSK_WITH_AES_256_CBC_SHA384', '⚠️ Weak'),
    '0x00b0': ('TLS_PSK_WITH_NULL_SHA256', '❌ Insecure'),
    '0x00b1': ('TLS_PSK_WITH_NULL_SHA384', '❌ Insecure'),
    '0x00b2': ('TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0x00b3': ('TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', '✅ Adequate'),
    '0x00b4': ('TLS_DHE_PSK_WITH_NULL_SHA256', '❌ Insecure'),
    '0x00b5': ('TLS_DHE_PSK_WITH_NULL_SHA384', '❌ Insecure'),
    '0x00b6': ('TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0x00b7': ('TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', '✅ Adequate'),
    '0x00b8': ('TLS_RSA_PSK_WITH_NULL_SHA256', '❌ Insecure'),
    '0x00b9': ('TLS_RSA_PSK_WITH_NULL_SHA384', '❌ Insecure'),
    '0x00ba': ('TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0x00bb': ('TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0x00bc': ('TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0x00bd': ('TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0x00be': ('TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0x00bf': ('TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA256', '❌ Insecure'),
    '0x00c0': ('TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', '⚠️ Weak'),
    '0x00c1': ('TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256', '⚠️ Weak'),
    '0x00c2': ('TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256', '⚠️ Weak'),
    '0x00c3': ('TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256', '✅ Adequate'),
    '0x00c4': ('TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256', '✅ Adequate'),
    '0x00c5': ('TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA256', '❌ Insecure'),
    '0x1301': ('TLS_AES_128_GCM_SHA256', '✅ Strong'),
    '0x1302': ('TLS_AES_256_GCM_SHA384', '✅ Strong'),
    '0x1303': ('TLS_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0x1304': ('TLS_AES_128_CCM_SHA256', '✅ Strong'),
    '0x1305': ('TLS_AES_128_CCM_8_SHA256', '✅ Adequate'),
    '0x16b7': ('TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256', '❌ Insecure'),
    '0x16b8': ('TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256', '❌ Insecure'),
    '0x16b9': ('TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384', '❌ Insecure'),
    '0x16ba': ('TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384', '❌ Insecure'),
    '0xc001': ('TLS_ECDH_ECDSA_WITH_NULL_SHA', '❌ Insecure'),
    '0xc002': ('TLS_ECDH_ECDSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0xc003': ('TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc004': ('TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0xc005': ('TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0xc006': ('TLS_ECDHE_ECDSA_WITH_NULL_SHA', '❌ Insecure'),
    '0xc007': ('TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0xc008': ('TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc009': ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0xc00a': ('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0xc00b': ('TLS_ECDH_RSA_WITH_NULL_SHA', '❌ Insecure'),
    '0xc00c': ('TLS_ECDH_RSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0xc00d': ('TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc00e': ('TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0xc00f': ('TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0xc010': ('TLS_ECDHE_RSA_WITH_NULL_SHA', '❌ Insecure'),
    '0xc011': ('TLS_ECDHE_RSA_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0xc012': ('TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc013': ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0xc014': ('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0xc015': ('TLS_ECDH_Anon_WITH_NULL_SHA', '❌ Insecure'),
    '0xc016': ('TLS_ECDH_Anon_WITH_RC4_128_SHA', '❌ Insecure'),
    '0xc017': ('TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc018': ('TLS_ECDH_Anon_WITH_AES_128_CBC_SHA', '❌ Insecure'),
    '0xc019': ('TLS_ECDH_Anon_WITH_AES_256_CBC_SHA', '❌ Insecure'),
    '0xc01a': ('TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc01b': ('TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc01c': ('TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc01d': ('TLS_SRP_SHA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0xc01e': ('TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0xc01f': ('TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', '⚠️ Weak'),
    '0xc020': ('TLS_SRP_SHA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0xc021': ('TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0xc022': ('TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', '⚠️ Weak'),
    '0xc023': ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0xc024': ('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', '✅ Adequate'),
    '0xc025': ('TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0xc026': ('TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', '⚠️ Weak'),
    '0xc027': ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0xc028': ('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', '✅ Adequate'),
    '0xc029': ('TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', '⚠️ Weak'),
    '0xc02a': ('TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', '⚠️ Weak'),
    '0xc02b': ('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0xc02c': ('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0xc02d': ('TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0xc02e': ('TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0xc02f': ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0xc030': ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0xc031': ('TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', '⚠️ Weak'),
    '0xc032': ('TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', '⚠️ Weak'),
    '0xc033': ('TLS_ECDHE_PSK_WITH_RC4_128_SHA', '⚠️ Weak'),
    '0xc034': ('TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xc035': ('TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', '✅ Adequate'),
    '0xc036': ('TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', '✅ Adequate'),
    '0xc037': ('TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256', '✅ Adequate'),
    '0xc038': ('TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384', '✅ Adequate'),
    '0xc039': ('TLS_ECDHE_PSK_WITH_NULL_SHA', '❌ Insecure'),
    '0xc03a': ('TLS_ECDHE_PSK_WITH_NULL_SHA256', '❌ Insecure'),
    '0xc03b': ('TLS_ECDHE_PSK_WITH_NULL_SHA384', '❌ Insecure'),
    '0xc03c': ('TLS_RSA_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc03d': ('TLS_RSA_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc03e': ('TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc03f': ('TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc040': ('TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc041': ('TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc042': ('TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc043': ('TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc044': ('TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc045': ('TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc046': ('TLS_DH_Anon_WITH_ARIA_128_CBC_SHA256', '❌ Insecure'),
    '0xc047': ('TLS_DH_Anon_WITH_ARIA_256_CBC_SHA384', '❌ Insecure'),
    '0xc048': ('TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc049': ('TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc04a': ('TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc04b': ('TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc04c': ('TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc04d': ('TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc04e': ('TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc04f': ('TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc050': ('TLS_RSA_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc051': ('TLS_RSA_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc052': ('TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', '✅ Strong'),
    '0xc053': ('TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', '✅ Strong'),
    '0xc054': ('TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc055': ('TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc056': ('TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', '✅ Adequate'),
    '0xc057': ('TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', '✅ Adequate'),
    '0xc058': ('TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc059': ('TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc05a': ('TLS_DH_Anon_WITH_ARIA_128_GCM_SHA256', '❌ Insecure'),
    '0xc05b': ('TLS_DH_Anon_WITH_ARIA_256_GCM_SHA384', '❌ Insecure'),
    '0xc05c': ('TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', '✅ Strong'),
    '0xc05d': ('TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', '✅ Strong'),
    '0xc05e': ('TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc05f': ('TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc060': ('TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', '✅ Strong'),
    '0xc061': ('TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', '✅ Strong'),
    '0xc062': ('TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc063': ('TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc064': ('TLS_PSK_WITH_ARIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc065': ('TLS_PSK_WITH_ARIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc066': ('TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc067': ('TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc068': ('TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc069': ('TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc06a': ('TLS_PSK_WITH_ARIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc06b': ('TLS_PSK_WITH_ARIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc06c': ('TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256', '✅ Strong'),
    '0xc06d': ('TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384', '✅ Strong'),
    '0xc06e': ('TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256', '✅ Strong'),
    '0xc06f': ('TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384', '✅ Strong'),
    '0xc070': ('TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc071': ('TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc072': ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc073': ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc074': ('TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc075': ('TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc076': ('TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc077': ('TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc078': ('TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc079': ('TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc07a': ('TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc07b': ('TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc07c': ('TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', '✅ Strong'),
    '0xc07d': ('TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', '✅ Strong'),
    '0xc07e': ('TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc07f': ('TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc080': ('TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256', '✅ Adequate'),
    '0xc081': ('TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384', '✅ Adequate'),
    '0xc082': ('TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc083': ('TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc084': ('TLS_DH_Anon_WITH_CAMELLIA_128_GCM_SHA256', '❌ Insecure'),
    '0xc085': ('TLS_DH_Anon_WITH_CAMELLIA_256_GCM_SHA384', '❌ Insecure'),
    '0xc086': ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', '✅ Strong'),
    '0xc087': ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', '✅ Strong'),
    '0xc088': ('TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc089': ('TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc08a': ('TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', '✅ Strong'),
    '0xc08b': ('TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', '✅ Strong'),
    '0xc08c': ('TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc08d': ('TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc08e': ('TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256', '⚠️ Weak'),
    '0xc08f': ('TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384', '⚠️ Weak'),
    '0xc090': ('TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256', '✅ Strong'),
    '0xc091': ('TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384', '✅ Strong'),
    '0xc092': ('TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256', '✅ Strong'),
    '0xc093': ('TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384', '✅ Strong'),
    '0xc094': ('TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256', '⚠️ Weak'),
    '0xc095': ('TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384', '⚠️ Weak'),
    '0xc096': ('TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc097': ('TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc098': ('TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc099': ('TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc09a': ('TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', '✅ Adequate'),
    '0xc09b': ('TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', '✅ Adequate'),
    '0xc09c': ('TLS_RSA_WITH_AES_128_CCM', '⚠️ Weak'),
    '0xc09d': ('TLS_RSA_WITH_AES_256_CCM', '⚠️ Weak'),
    '0xc09e': ('TLS_DHE_RSA_WITH_AES_128_CCM', '✅ Strong'),
    '0xc09f': ('TLS_DHE_RSA_WITH_AES_256_CCM', '✅ Strong'),
    '0xc0a0': ('TLS_RSA_WITH_AES_128_CCM_8', '⚠️ Weak'),
    '0xc0a1': ('TLS_RSA_WITH_AES_256_CCM_8', '⚠️ Weak'),
    '0xc0a2': ('TLS_DHE_RSA_WITH_AES_128_CCM_8', '✅ Adequate'),
    '0xc0a3': ('TLS_DHE_RSA_WITH_AES_256_CCM_8', '✅ Adequate'),
    '0xc0a4': ('TLS_PSK_WITH_AES_128_CCM', '⚠️ Weak'),
    '0xc0a5': ('TLS_PSK_WITH_AES_256_CCM', '⚠️ Weak'),
    '0xc0a6': ('TLS_DHE_PSK_WITH_AES_128_CCM', '✅ Strong'),
    '0xc0a7': ('TLS_DHE_PSK_WITH_AES_256_CCM', '✅ Strong'),
    '0xc0a8': ('TLS_PSK_WITH_AES_128_CCM_8', '⚠️ Weak'),
    '0xc0a9': ('TLS_PSK_WITH_AES_256_CCM_8', '⚠️ Weak'),
    '0xc0aa': ('TLS_PSK_DHE_WITH_AES_128_CCM_8', '✅ Adequate'),
    '0xc0ab': ('TLS_PSK_DHE_WITH_AES_256_CCM_8', '✅ Adequate'),
    '0xc0ac': ('TLS_ECDHE_ECDSA_WITH_AES_128_CCM', '✅ Strong'),
    '0xc0ad': ('TLS_ECDHE_ECDSA_WITH_AES_256_CCM', '✅ Strong'),
    '0xc0ae': ('TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', '✅ Adequate'),
    '0xc0af': ('TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8', '✅ Adequate'),
    '0xcc13': ('TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_D', '✅ Adequate'),
    '0xcc14': ('TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_D', '✅ Adequate'),
    '0xcc15': ('TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_D', '✅ Adequate'),
    '0xcca8': ('TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xcca9': ('TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xccaa': ('TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xccab': ('TLS_PSK_WITH_CHACHA20_POLY1305_SHA256', '⚠️ Weak'),
    '0xccac': ('TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xccad': ('TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xccae': ('TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256', '✅ Strong'),
    '0xd001': ('TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256', '✅ Strong'),
    '0xd002': ('TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384', '✅ Strong'),
    '0xd003': ('TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256', '✅ Adequate'),
    '0xd004': ('TLS_ECDHE_PSK_WITH_AES_256_CCM_8_SHA256', '✅ Adequate'),
    '0xd005': ('TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256', '✅ Strong'),
    '0xd006': ('TLS_ECDHE_PSK_WITH_AES_256_CCM_SHA384', '✅ Strong'),
    '0xfefe': ('SSL_RSA_FIPS_WITH_DES_CBC_SHA', '❌ Insecure'),
    '0xfeff': ('SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xffe0': ('SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', '❌ Insecure'),
    '0xffe1': ('SSL_RSA_FIPS_WITH_DES_CBC_SHA', '❌ Insecure')
}

SIG_ALGO_MAP = {
    '1.2.840.113549.1.1.11': ('sha256WithRSAEncryption', '✅ Standard'),
    '1.2.840.113549.1.1.12': ('sha384WithRSAEncryption', '✅ Standard'),
    '1.2.840.10045.4.3.2': ('ecdsa-with-SHA256', '✅ Standard'),
    '1.2.840.113549.1.1.5': ('sha1WithRSAEncryption', '⚠️ Outdated (SHA-1)'),
    '1.2.840.113549.1.1.4': ('md5WithRSAEncryption', '⚠️ Outdated (MD5)')
}

is_analyzing = True 

def animate_spinner():
    """Runs a smooth terminal spinner in a background thread."""
    spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
    while is_analyzing:
        sys.stdout.write(f"\r\033[96m[!] Deep Packet Inspection running... {next(spinner)}\033[0m ")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r\033[92m[✔] Deep Packet Inspection complete!          \033[0m\n')

def main():
    print(BANNER)
    
    pcap_input = input(f"{Y}[?] Enter the PCAP file name (or drag-and-drop here): {W}").strip()
    if pcap_input.startswith("& "): pcap_input = pcap_input[2:].strip()
    PCAP_FILE = pcap_input.strip("\"'") 
    
    camera_ip = input(f"{Y}[?] Enter the IoT / IP Camera device IP address: {W}").strip()

    if pcap_input.startswith("& "): pcap_input = pcap_input[2:].strip()
    PCAP_FILE = pcap_input.strip("\"'") 
    camera_ip = input("Enter the IoT / IP Camera device IP address: ").strip()

    print(f"\n[+] Analyzing '{PCAP_FILE}' for IP: {camera_ip}...")

    global is_analyzing
    is_analyzing = True
    
    spinner_thread = threading.Thread(target=animate_spinner)
    spinner_thread.start()

    try:
        cap = pyshark.FileCapture(PCAP_FILE, display_filter=f"ip.addr == {camera_ip} or arp")
    except FileNotFoundError:
        is_analyzing = False 
        spinner_thread.join()
        print(f"\n❌ Error: Could not find the file at path: {PCAP_FILE}")
        sys.exit(1)

    mac_address, hostname = "❌ Not Found", "❌ Not Found"
    outbound_ips = {}
    http_traffic = []
    tls_detected = False

    protocols = {
        "RTP": {"status": "❌ Not Found", "src": "", "dst": "", "info": ""},
        "SRTP": {"status": "❌ Not Found", "src": "", "dst": "", "info": ""},
        "RTSP": {"status": "❌ Not Found", "src": "", "dst": "", "info": ""},
        "Telnet": {"status": "❌ Not Found", "src": "", "dst": "", "info": "-"},
        "SSH": {"status": "❌ Not Found", "src": "", "dst": "", "info": "-"},
        "MQTT": {"status": "❌ Not Found", "src": "", "dst": "", "info": "-"},
        "MQTTS": {"status": "❌ Not Found", "src": "", "dst": "", "info": "-"},
        "FTP": {"status": "❌ Not Found", "src": "", "dst": "", "info": "-"}
    }

    tls_info = {
        "version": {"status": "❌ Not Found", "info": "-"},
        "cipher": {"status": "❌ Not Found", "info": "-"},
        "sig_alg": {"status": "❌ Not Found", "info": "-"},
        "validity": {"status": "❌ Not Found", "info": "-"},
        "issuer": {"status": "❌ Not Found", "info": "-"}
    }

    for pkt in cap:
        try:
            if hasattr(pkt, 'eth') and hasattr(pkt, 'ip') and pkt.ip.src == camera_ip and mac_address == "❌ Not Found":
                mac_address = pkt.eth.src
            
            if hasattr(pkt, 'dhcp') and hasattr(pkt.dhcp, 'option_hostname'):
                hostname = pkt.dhcp.option_hostname
            
            if not hasattr(pkt, 'ip'): continue

            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            if src_ip == camera_ip and not is_private_ip(dst_ip): 
                if dst_ip not in outbound_ips: 
                    outbound_ips[dst_ip] = set()
                
                proto = pkt.highest_layer
                
                if proto in ['JSON', 'XML', 'URLENCODED', 'MEDIA']:
                    if hasattr(pkt, 'http'):
                        proto = 'HTTP'
                    elif hasattr(pkt, 'ssdp'):
                        proto = 'SSDP'
                
                elif proto == 'DATA' and hasattr(pkt, 'transport_layer'):
                    proto = pkt.transport_layer
                    
                outbound_ips[dst_ip].add(proto.upper())

            src_port = pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else ""
            dst_port = pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else ""
            sd_pair, ds_pair = f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"

            # Protocol detection-
            if hasattr(pkt, 'rtp'):
                pt = pkt.rtp.p_type
                codec_name = RTP_PAYLOAD_MAP.get(pt, f"Dynamic (Type {pt} - Usually H.264/H.265 Video or AAC Audio)")
                protocols["RTP"]["status"] = "⚠️ Found"
                protocols["RTP"]["src"], protocols["RTP"]["dst"] = sd_pair, ds_pair
                protocols["RTP"]["info"] = codec_name
            elif hasattr(pkt, 'srtp'):
                protocols["SRTP"]["status"] = "✅ Standard SRTP was Used"
                protocols["SRTP"]["src"], protocols["SRTP"]["dst"] = sd_pair, ds_pair
            
            if hasattr(pkt, 'rtsp'):
                if hasattr(pkt.rtsp, 'auth_credentials') or hasattr(pkt.rtsp, 'authorization'):
                    protocols["RTSP"]["status"] = "✅ Authentication Header Exist"
                    protocols["RTSP"]["info"] = "Auth Found"
                elif protocols["RTSP"]["status"] == "❌ Not Found":
                    protocols["RTSP"]["status"] = "⚠️ Found (No Auth Detected)"
                protocols["RTSP"]["src"], protocols["RTSP"]["dst"] = sd_pair, ds_pair

            if dst_port == '23' or src_port == '23': protocols["Telnet"].update({"status": "⚠️ Found", "src": sd_pair, "dst": ds_pair})
            elif dst_port == '22' or src_port == '22': protocols["SSH"].update({"status": "✅ Standard SSH was Used", "src": sd_pair, "dst": ds_pair})
            
            if dst_port == '21' or src_port == '21' or hasattr(pkt, 'ftp'):
                protocols["FTP"].update({"status": "⚠️ Found", "src": sd_pair, "dst": ds_pair})

            if hasattr(pkt, 'http') and dst_ip != "239.255.255.250":
                if hasattr(pkt.http, 'request_method') and src_ip == camera_ip:
                    req_host = getattr(pkt.http, 'host', 'Unknown')
                    req_uri = getattr(pkt.http, 'request_uri', 'Unknown')
                    payload_sum = req_uri[:50] + "..." if len(req_uri) > 50 else req_uri
                    
                    country, _ = get_geolocation(dst_ip)
                    
                    entry = [sd_pair, ds_pair, country, req_host, payload_sum]
                    if entry not in http_traffic: 
                        http_traffic.append(entry)

            # DEEP TLS checking
            if hasattr(pkt, 'tls'):
                tls_detected = True
                # TLS Version
                if hasattr(pkt.tls, 'handshake_version'):
                    hex_ver = pkt.tls.handshake_version
                    if hex_ver == '0x0304': tls_info['version'] = {"status": "✅ Standard", "info": "TLS 1.3"}
                    elif hex_ver == '0x0303': tls_info['version'] = {"status": "✅ Standard", "info": "TLS 1.2"}
                    elif hex_ver in ['0x0302', '0x0301', '0x0300']: tls_info['version'] = {"status": "⚠️ Outdated", "info": "TLS 1.1 or lower"}

                # Cipher Suite
                if hasattr(pkt.tls, 'handshake_ciphersuite'):
                    try:
                        c_int = int(pkt.tls.handshake_ciphersuite, 0)
                        c_hex = f"0x{c_int:04x}" 
                        
                        if c_hex in CIPHER_MAP:
                            name, grade = CIPHER_MAP[c_hex]
                            tls_info['cipher'] = {"status": grade, "info": name}
                        else:
                            tls_info['cipher'] = {"status": "⚠️ Unknown/Other", "info": c_hex}
                    except: pass

                # Certificate Signature & Issuer
                if hasattr(pkt.tls, 'x509af_algorithm_id'):
                    oid = str(pkt.tls.x509af_algorithm_id).split(',')[0] # get primary OID
                    for key, val in SIG_ALGO_MAP.items():
                        if key in oid:
                            tls_info['sig_alg'] = {"status": val[1], "info": val[0]}
                            break
                    if tls_info['sig_alg']['status'] == "❌ Not Found":
                        tls_info['sig_alg'] = {"status": "⚠️ Found", "info": f"OID: {oid}"}

                # Extract Issuer / Subject string
                if hasattr(pkt.tls, 'x509sat_printableString') or hasattr(pkt.tls, 'x509sat_uTF8String'):
                    issuer_parts = []
                    if hasattr(pkt.tls, 'x509sat_printableString'): issuer_parts.append(str(pkt.tls.x509sat_printableString).replace('\n', ', '))
                    if hasattr(pkt.tls, 'x509sat_uTF8String'): issuer_parts.append(str(pkt.tls.x509sat_uTF8String).replace('\n', ', '))
                    
                    if issuer_parts:
                        clean_issuer = " | ".join(issuer_parts)
                        if len(clean_issuer) > 65: clean_issuer = clean_issuer[:62] + "..." # Truncate for table
                        tls_info['issuer'] = {"status": "⚠️ Extracted", "info": clean_issuer}

                # Certificate Validity
                if hasattr(pkt.tls, 'x509af_utc_time'):
                    times = str(pkt.tls.x509af_utc_time).split(',')
                    if len(times) >= 2:
                        tls_info['validity'] = {"status": "⚠️ Found", "info": f"Expires: {times[1].strip()}"}

        except Exception as e:
            continue
    cap.close()
    
    is_analyzing = False
    spinner_thread.join()
    time.sleep(0.5)

    rtp_res = protocols["SRTP"] if protocols["SRTP"]["status"] != "❌ Not Found" else protocols["RTP"]
    telnet_res = protocols["SSH"] if protocols["SSH"]["status"] != "❌ Not Found" else protocols["Telnet"]
    mqtt_res = protocols["MQTTS"] if protocols["MQTTS"]["status"] != "❌ Not Found" else protocols["MQTT"]

    print("\nDevice Hostname:", hostname)
    print("Device IP Address:", camera_ip)
    print("Device MAC Address:", mac_address)

    print("\n[🔓] Unencrypted Protocol Detection [🔓]")
    proto_headers = ["Metrics", "Result", "Source IP & Port", "Destination IP & Port", "Info"]
    proto_table = [
        ["Unencrypted Video Streams (RTP)", rtp_res["status"], rtp_res["src"], rtp_res["dst"], rtp_res["info"]],
        ["RTSP without Authentication", protocols["RTSP"]["status"], protocols["RTSP"]["src"], protocols["RTSP"]["dst"], protocols["RTSP"]["info"]],
        ["Outdated Telnet", telnet_res["status"], telnet_res["src"], telnet_res["dst"], telnet_res["info"]],
        ["MQTT without TLS", mqtt_res["status"], mqtt_res["src"], mqtt_res["dst"], mqtt_res["info"]],
        ["FTP", protocols["FTP"]["status"], protocols["FTP"]["src"], protocols["FTP"]["dst"], protocols["FTP"]["info"]]
    ]
    print(tabulate(proto_table, headers=proto_headers, tablefmt="github"))

    print("\nHTTP Plaintext Traffic:")
    if http_traffic:
        http_headers = ["Source IP & Port", "Destination IP & Port", "Country", "Hostname", "Payloads"]
        print(tabulate(http_traffic, headers=http_headers, tablefmt="github"))
    else:
        print("❌ No plaintext HTTP traffic found.")

    print("\n[🔓] TLS / Encryption Quality [🔓]")
    tls_headers = ["Metrics", "Result", "Info"]

    if not tls_detected:
        tls_table = [
            ["Transport Layer Security", "🚨 CRITICAL", "No TLS Handshake detected, network traffic is unencrypted (plaintext)."]
        ]
    else:
        tls_table = [
            ["TLS Version", tls_info["version"]["status"], tls_info["version"]["info"]],
            ["Cipher Suite", tls_info["cipher"]["status"], tls_info["cipher"]["info"]],
            ["Certificate Signature", tls_info["sig_alg"]["status"], tls_info["sig_alg"]["info"]],
            ["Certificate Validity", tls_info["validity"]["status"], tls_info["validity"]["info"]],
            ["Certificate Issuer", tls_info["issuer"]["status"], tls_info["issuer"]["info"]]
        ]
        
    print(tabulate(tls_table, headers=tls_headers, tablefmt="github"))

    print("\n[ℹ️] Outbound Geolocation & OSINT Threat Intel")
    
    geo_headers = [
        "Destination IP", 
        "Country", 
        "ASN & Organization", 
        "Botnet Intel (Abuse.ch)", 
        "Surface OSINT (Shodan)"
    ]
    geo_table = []
    
    if outbound_ips:
        for ip, protos in outbound_ips.items():
            country, asn = get_geolocation(ip)
            
            botnet_reputation = check_threat_intel(ip)
            shodan_reputation = check_shodan_osint(ip)
            
            geo_table.append([ip, country, asn, botnet_reputation, shodan_reputation])

        geo_table.sort(key=lambda x: (x[1], x[0]))
        
        print(tabulate(geo_table, headers=geo_headers, tablefmt="github"))
    else:
        print("❌ No outbound external IPs detected.")
    print("\n==================================================")

if __name__ == "__main__":
    main()