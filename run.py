import os
import json
import argparse
from util import run_scanner  # Pastikan file util.py ada dan berisi fungsi run_scanner

# Warna ANSI
red = '\033[31m'
green = '\033[32m'
cyan = '\033[34m'
reset = '\033[0m'

# Clear layar (opsional)
os.system('clear')

# Banner dengan figlet
figlet_output = os.popen("figlet -f small 'XSS - HUNTER'").read()

# Baca versi dari JSON
try:
    with open('settings/version.json', 'r') as f:
        v = json.load(f)
        version = v["Version"]
except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
    print(f"{red}[ERROR]{reset} Gagal membaca settings/version.json: {e}")
    version = "Unknown"

# Argumen CLI
def main():
    parser = argparse.ArgumentParser(description="XSS HUNTER CLI")
    parser.add_argument("--target", type=str, required=True, help="Target URL")
    parser.add_argument("-pt", type=int, help="Jumlah payload yang diuji", default=None)
    parser.add_argument("-sm", "--select-mode", type=str.lower, choices=["normal", "god"], default="normal", help="Pilih mode: normal atau god")
    args = parser.parse_args()

    # Cetak Banner
    print(f"{red}{figlet_output}{reset}")
    print(f'{cyan}TOOLS NAME : {reset}XSS - HUNTER')
    print(f'{cyan}DEVELOPER  : {reset}./Bio404Xploit')
    print(f'{cyan}VERSION    : {reset}{version}')

    # Validasi versi
    official_version = "1.0"  # Ganti sesuai versi resmi
    if version == official_version:
        print(f'{cyan}STATUS     : {green}OFFICIAL VERSION{reset}\n')
    else:
        print(f'{cyan}STATUS     : {red}RECODE VERSION{reset}\n')

    run_scanner(args.target, args.pt)

    # Mode
    if args.select_mode == "god":
        print(f'{cyan}[ {red}GOD MODE{cyan} ]{reset}')
    else:
        print(f'{cyan}[ NORMAL MODE ]{reset}')

if __name__ == "__main__":
    main()
