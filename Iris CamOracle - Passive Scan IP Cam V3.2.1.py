import pyshark
import requests
import ipaddress
import sys
import threading
import time
import itertools
import re
import textwrap
from datetime import datetime
from tabulate import tabulate
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
{Y} > Version:{W} 3.2.1
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
    
    # cache to avoid API requests limit hit
    if ip in THREAT_CACHE: return THREAT_CACHE[ip]
    
    try:
        #Query ThreatFox Abuse.ch
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ip}
        
        #POST request required by Threatfox
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
                SHODAN_CACHE[ip] = " - ".join(result)
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

# list for common RTP payloads types
RTP_PAYLOAD_MAP = {
    '0': 'PCMU (Audio)', '8': 'PCMA (Audio)', '26': 'JPEG (Video)', '33': 'MP2T (Video)', '34': 'H.263 (Video)'
}

# List for mapping Cipher Suites hex - string names (Source: Broadcom SymantecSSL)
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
    '1.2.840.113549.1.1.5': ('sha1WithRSAEncryption', '⚠️ Outdated (SHA1)'),
    '1.2.840.113549.1.1.4': ('md5WithRSAEncryption', '⚠️ Outdated (MD5)')
}

is_analyzing = True 

def animate_spinner():
    # useless spin animation loading :D
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
    
    if pcap_input.startswith("& "): pcap_input = pcap_input[2:].strip()
    PCAP_FILE = pcap_input.strip("\"'") 
    camera_ip = input("Enter the IoT / IP Camera device IP address: ").strip()

    print(f"\n[+] Analyzing '{PCAP_FILE}' for IP: {camera_ip}...")

    global is_analyzing
    is_analyzing = True
    
    spinner_thread = threading.Thread(target=animate_spinner)
    spinner_thread.daemon = True 
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

    first_pkt_time = None
    outbound_times = []
    outbound_sizes = []

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

            if first_pkt_time is None:
                first_pkt_time = float(pkt.sniff_timestamp)

            if hasattr(pkt, 'eth') and hasattr(pkt, 'ip') and pkt.ip.src == camera_ip and mac_address == "❌ Not Found":
                mac_address = pkt.eth.src
            
            if hasattr(pkt, 'dhcp') and hasattr(pkt.dhcp, 'option_hostname'):
                hostname = pkt.dhcp.option_hostname
            
            if not hasattr(pkt, 'ip'): continue

            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            
            # Extract ports
            src_port = pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else ""
            dst_port = pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else ""
            sd_pair, ds_pair = f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"

            #Outbound traffic tracking
            if src_ip == camera_ip and not is_private_ip(dst_ip): 

                rel_time = float(pkt.sniff_timestamp) - first_pkt_time
                if rel_time <= 360: 
                    outbound_times.append(rel_time)
                    outbound_sizes.append(int(pkt.length))
                    
                if dst_ip not in outbound_ips: 
                    outbound_ips[dst_ip] = set()
                
                proto = pkt.highest_layer
                if proto in ['JSON', 'XML', 'URLENCODED', 'MEDIA']:
                    if hasattr(pkt, 'http'): proto = 'HTTP'
                    elif hasattr(pkt, 'ssdp'): proto = 'SSDP'
                elif proto == 'DATA' and hasattr(pkt, 'transport_layer'):
                    proto = pkt.transport_layer
                
                # x11 protocol false positive
                if proto and proto.upper() == 'X11' and dst_port == '6010':
                    proto = 'CUSTOM_VIDEO'

                # save dst port
                if dst_port:
                    outbound_ips[dst_ip].add(f"{proto.upper()}:{dst_port}")
                else:
                    outbound_ips[dst_ip].add(proto.upper())

            # Protocol detection
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

            # Check for false positive - TCP Reset (RST) check
            is_reset = False
            if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'flags'):
                try:
                    #read the raw TCP flags as integer
                    tcp_flags = int(pkt.tcp.flags, 16)
                    
                    # Use bitwise AND operator to check if the RST bit (0x04) active
                    if tcp_flags & 0x04: 
                        is_reset = True
                except ValueError:
                    pass

            # Telnet check: only trigger if camera sends traffic from port 23 (without resetting)
            if src_ip == camera_ip and src_port == '23' and not is_reset: 
                protocols["Telnet"].update({"status": "⚠️ Found", "src": sd_pair, "dst": ds_pair})
            
            #SSH check: only trigger if camera sends trafic from port 22 (without resetting)
            elif src_ip == camera_ip and src_port == '22' and not is_reset: 
                protocols["SSH"].update({"status": "✅ Standard SSH was Used", "src": sd_pair, "dst": ds_pair})
            
            #FTP check: trigger only if camera sends traffic from port 21 safely or actual ftp data exists ril no fek
            if (src_ip == camera_ip and src_port == '21' and not is_reset) or hasattr(pkt, 'ftp'):
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

            # deep TLS checking
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

                # Certificate Signature & issuer
                if hasattr(pkt.tls, 'x509af_algorithm_id'):
                    oid = str(pkt.tls.x509af_algorithm_id).split(',')[0]
                    for key, val in SIG_ALGO_MAP.items():
                        if key in oid:
                            tls_info['sig_alg'] = {"status": val[1], "info": val[0]}
                            break
                    if tls_info['sig_alg']['status'] == "❌ Not Found":
                        tls_info['sig_alg'] = {"status": "⚠️ Found", "info": f"OID: {oid}"}

                #Extract the issuer / subject string (raw hex try), no annoying regex anynmore :)))
                if hasattr(pkt.tls, 'handshake_certificate'):
                    try:
                        # get raw hex and remove the colons
                        raw_cert_hex = pkt.tls.handshake_certificate.replace(':', '')
                        cert_bytes = bytes.fromhex(raw_cert_hex)
                        
                        # uusing cryptography library read the ASN.1 binary
                        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        
                        # extract string (CN=DigiCert Global Root, O=DigiCert Inc)
                        exact_issuer = cert.issuer.rfc4514_string()
                        
                        display_issuer = textwrap.fill(exact_issuer, width=55)
                            
                        # trusted CA list
                        trusted_cas = ['DigiCert', 'Let\'s Encrypt', 'GlobalSign', 'Sectigo', 'Amazon', 'GoDaddy']
                        is_trusted = any(ca.lower() in exact_issuer.lower() for ca in trusted_cas)
                        
                        if is_trusted:
                            tls_info['issuer'] = {"status": "✅ Trusted Public CA", "info": display_issuer}
                        else:
                            tls_info['issuer'] = {"status": "⚠️ Private / Untrusted CA", "info": display_issuer}
                    except Exception:
                        pass

                # Certificate validity check
                tls_text = str(pkt.tls)
                times = re.findall(r'(?:utcTime|generalizedTime):\s*(.*?)(?:\r|\n|$)', tls_text)
                if len(times) >= 2:
                    not_after = times[1].strip()
                    
                    # long timezone strings clean / shortener for table
                    clean_date_match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', not_after)
                    if clean_date_match:
                        display_exp = clean_date_match.group(1)
                    else:
                        display_exp = not_after.split('.')[0].strip()
                        
                    status = "✅ Active"
                    info_str = f"Exp: {display_exp}"
                    
                    try:
                        #Extract year to count the expiration when yh
                        year_match = re.search(r'\b(20\d{2})\b', not_after)
                        if year_match:
                            exp_year = int(year_match.group(1))
                            current_year = datetime.now().year
                            
                            if exp_year < current_year:
                                status = "🚨 Expired"
                            elif exp_year == current_year:
                                status = "⚠️ Expiring This Year"
                            elif exp_year > current_year + 5: 
                                status = "⚠️ Non-Compliant (Excessive Lifespan)" 
                    except:
                        pass
                        
                    tls_info['validity'] = {"status": status, "info": info_str}

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

    print("\nUnencrypted Protocol Detection")
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

    print("\nTLS / Encryption Quality")
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

    # Excessive lifespan warning
    if tls_info["validity"]["status"] == "⚠️ Non-Compliant (Excessive Lifespan)":
        print(f"\n{Y}Excessive certificate lifespans: systems vulnerable to outdated cryptographic algorithms and delay necessary security updates,{W}")
        print("If private key is compromised or a certificate is mis-issued, will give attacker long validity periods to exploit.")

    if tls_detected:
        print(f"\nNote: Certificate issuer extracted from raw ASN.1 binary for precision instead of using regex.{W}")
        print(f"{C}Known Trusted CAs checked: DigiCert, Let's Encrypt, GlobalSign, Sectigo, Amazon, GoDaddy.{W}")

    print("\nℹ️  Outbound Geolocation & OSINT Threat Intel")
    
    geo_headers = [
        "",
        "Destination IP",
        "Country",
        "ASN & Organization",
        "Dest Ports Used",
        "Botnet Intel (Abuse.ch)",
        "Surface OSINT (Shodan)"
    ]
    geo_table = []
    
    if outbound_ips:
        for ip, protos in outbound_ips.items():
            country, asn = get_geolocation(ip)
            
            botnet_reputation = check_threat_intel(ip)
            shodan_reputation = check_shodan_osint(ip)

            raw_ports = ", ".join(sorted(list(protos)))
            ports_used = textwrap.fill(raw_ports, width=45)
            
            alert_flag = "\u3000" 
            if country not in ["Indonesia", "Local Network", "Unknown"]:
                if any(p in raw_ports for p in ["HTTP", "HTTPS", "TLS", "TCP"]):
                    alert_flag = "🔴"
            
            geo_table.append([alert_flag, ip, country, asn, ports_used, botnet_reputation, shodan_reputation])

        geo_table.sort(key=lambda x: (x[2], x[1]))
        
        print(tabulate(geo_table, headers=geo_headers, tablefmt="github"))
    else:
        print("❌ No outbound external IPs detected.")
        
    # Threat intel alert context info
    table_text = str(geo_table).lower()

    # Cross-border data indonesia warning
    print(f"\n{Y}Cross border data & privacy jurisdiction:{W}")
    print("🔴 HTTP / HTTPS / TLS / TCP: Connections abroad may indicate user data is processed/stored outside Indonesia.")
    print("🟢 NTP/STUN: Used for basic internet time sync and router checks (Safe)")

    #x11 false positive fp disclaimer/warning fyi
    if "custom_video" in table_text:
        print(f"\nNote: Wireshark blindly labels port 6010 as X11. Some IP cameras use this port for P2P video streams (not SSH backdoors). This script overrides the label to CUSTOM_VIDEO.{W}")

    # Supply chain attack warning for vulns or eol
    if "vuln" in table_text or "eol" in table_text:
        print(f"\n{R}⚠️ Supply Chain Warning:{W}")
        print(f"The vendor's cloud infrastructure contains known vulnerabilities or End-of-Life (EOL) software.")
        print(f"User data is potentially exposed to third-party remote breaches (supply chain attacks).")
    print("\n==================================================")

    
    print(f"\n{C}Traffic Frequency Analysis by Scenario{W}")
    try:
        import matplotlib.pyplot as plt
        import os

        # Scenarios lable
        scenarios = [
            (0, 60, "1. Camera Startup", "#FF9999"),          
            (60, 120, "2. Idle (Alarm On)", "#99FF99"),       
            (120, 180, "3. Motion (Alarm On)", "#9999FF"),    
            (180, 240, "4. Accessing App", "#FFFF99"),        
            (240, 300, "5. Live Camera View", "#FFCC99"),     
            (300, 360, "6. Motion (Alarm Off)", "#99FFFF")    
        ]

        scenario_table = []
        scenario_labels = []
        scenario_totals = []
        scenario_colors = []

        # Table calculation
        for start, end, label, color in scenarios:
            window_pkts = [size for t, size in zip(outbound_times, outbound_sizes) if start <= t < end]
            total_packets = len(window_pkts)
            
            avg_per_sec = total_packets / (end - start)
            avg_size = sum(window_pkts) / total_packets if total_packets > 0 else 0
                
            scenario_table.append([
                label, 
                f"{start}s - {end}s", 
                f"{total_packets} pkts", 
                f"{avg_per_sec:.2f} pkt/s",
                f"{avg_size:.0f} Bytes"
            ])
            
            scenario_labels.append(label.split(". ")[1])
            scenario_totals.append(total_packets)
            scenario_colors.append(color)
            
        freq_headers = ["Scenario Phase", "Time Window", "Total Packets", "Avg Frequency", "Avg Packet Size"]
        print(tabulate(scenario_table, headers=freq_headers, tablefmt="github"))
        print("\n")

        # Kibana style time series Histogram
        print(f"{C}[*] Generating Kibana-Style Traffic Histogram...{W}")
        import matplotlib.patches as mpatches
        
        plt.figure(figsize=(14, 6))

        #time buckets interval 2 secs
        bin_size = 2 
        num_bins = int(360 / bin_size)
        x_bins = [i * bin_size for i in range(num_bins)]
        y_counts = [0] * num_bins

        # frequency buckets
        for t in outbound_times:
            idx = int(t // bin_size)
            if idx < num_bins:
                y_counts[idx] += 1

        # Draw histogram bars
        plt.bar(x_bins, y_counts, width=bin_size, color='#1BA39C', align='edge', edgecolor='black', linewidth=0.3)

        #Scenario Background zones and the legend
        legend_patches = []
        for start, end, label, color in scenarios:
            plt.axvspan(start, end, color=color, alpha=0.25) # Soft pastel background
            legend_patches.append(mpatches.Patch(color=color, alpha=0.5, label=label))

        # graph style
        plt.title(f"IP Cam Outbound Traffic Dynamics ({camera_ip})", fontsize=14, fontweight='bold')
        plt.xlabel("Timeline (Seconds from Capture Start)", fontsize=12)
        plt.ylabel("Packets per 2-Second Bucket", fontsize=12)
        plt.xlim(0, 360)
        plt.ylim(bottom=0)

        # put legend safely outside graph area
        plt.legend(handles=legend_patches, loc='center left', bbox_to_anchor=(1.02, 0.5), title="Activity Scenarios")
        plt.grid(axis='y', linestyle='--', alpha=0.5)
        plt.tight_layout()
        
        # save image png
        pcap_dir = os.path.dirname(os.path.abspath(PCAP_FILE))
        safe_ip = camera_ip.replace('.', '_')
        img_filename = f"Histogram_Chart_{safe_ip}.png"
        out_img = os.path.join(pcap_dir, img_filename)
        
        plt.savefig(out_img, dpi=300)
        print(f"{G}[+] Histogram chart saved successfully next to your PCAP at:{W}")
        print(f"    {C}➔ {out_img}{W}\n")
        
    except ImportError:
        print(f"{Y}[!] 'matplotlib' is not installed. Run: pip install matplotlib for visualization :D {W}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        is_analyzing = False
        print(f"\n\n\033[31mScan aborted by user. Exiting...\033[0m")
        sys.exit(0)