"""Centralized configuration for Recon Dashboard v2."""
import os

SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
CENSYS_API_ID = os.environ.get('CENSYS_API_ID', '')
CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
DB_PATH = os.environ.get('RECON_DB', '/home/kali/recon-dashboard/recon.db')

SNAPSHOT_HOURS_UTC = [2, 10, 18]
CONSOLIDATE_HOUR_UTC = 19
DISCORD_HOUR_UTC = 20

PRIORITY_COUNTRIES = ['IR', 'RU', 'UA', 'CN', 'KP', 'IL', 'SY']

COUNTRIES = {
    'IR': 'Iran', 'RU': 'Russia', 'CN': 'China', 'US': 'United States',
    'KP': 'North Korea', 'UA': 'Ukraine', 'IL': 'Israel', 'SY': 'Syria',
    'IQ': 'Iraq', 'AF': 'Afghanistan', 'PK': 'Pakistan', 'IN': 'India',
    'TR': 'Turkey', 'SA': 'Saudi Arabia', 'AE': 'UAE', 'EG': 'Egypt',
    'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France', 'JP': 'Japan',
    'KR': 'South Korea', 'BR': 'Brazil', 'MX': 'Mexico', 'TW': 'Taiwan',
    'CU': 'Cuba', 'BY': 'Belarus', 'NG': 'Nigeria', 'VE': 'Venezuela',
}

# All 33 sectors
SECTORS = {
    'all': '', 'scada': 'port:502', 'cameras_hikvision': 'product:Hikvision',
    'cameras_dahua': 'product:Dahua', 'databases_mysql': 'port:3306',
    'databases_mongo': 'port:27017', 'databases_postgres': 'port:5432',
    'databases_redis': 'port:6379', 'databases_elastic': 'port:9200',
    'rdp': 'port:3389', 'ssh': 'port:22', 'web_http': 'port:80',
    'web_https': 'port:443', 'web_8080': 'port:8080', 'smb': 'port:445',
    'telnet': 'port:23', 'vpn_openvpn': 'port:1194', 'vpn_pptp': 'port:1723',
    'medical_dicom': 'port:104', 'printers': 'port:9100',
    'mikrotik': 'product:MikroTik', 'ftp': 'port:21', 'dns': 'port:53',
    'mail_smtp': 'port:25', 'voip': 'port:5060', 'modbus': 'port:502',
    'ics_s7': 'port:102', 'ics_bacnet': 'port:47808', 'ics_dnp3': 'port:20000',
    'ics_ethernetip': 'port:44818', 'windows_iis': 'product:"Microsoft IIS"',
    'apache': 'product:Apache', 'nginx': 'product:nginx',
}

# 12 key sectors for daily IP-level tracking (balances coverage vs API credits)
TRACKED_SECTORS = [
    'all', 'scada', 'cameras_hikvision', 'databases_mysql',
    'databases_mongo', 'databases_elastic', 'rdp', 'ssh',
    'smb', 'telnet', 'mikrotik', 'ics_s7',
]

MAX_NMAP_PER_DAY = 10
MIN_CONFIDENCE = 0.5
CENSYS_DAILY_BUDGET = 8
SHODAN_RESULTS_PER_QUERY = 100  # first page only
