import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote
import json
from colorama import Fore, Style, init
from html import escape
import os

# Inisialisasi warna terminal
init(autoreset=True)
success = Fore.GREEN + "[✓]" + Style.RESET_ALL
warning = Fore.YELLOW + "[!]" + Style.RESET_ALL
error = Fore.RED + "[x]" + Style.RESET_ALL
info = Fore.CYAN + "[*]" + Style.RESET_ALL
url_vuln = Fore.RED + Style.BRIGHT
get_ok = Fore.GREEN + Style.BRIGHT

# Load konfigurasi rahasia (opsional)
def load_secret_config(path="config/core.secret"):
    config = {}
    if not os.path.exists(path):
        print(f"{warning} Tidak ditemukan: {path} (lewati config)")
        return config
    try:
        with open(path, "r") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"{error} Gagal membaca config: {e}")
    return config

# Load payload dari JSON
def load_payloads(file_path, limit=None):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            payloads = data.get("payloads", [])
            if limit:
                return payloads[:limit], data.get("tool", "XSS HUNTER")
            return payloads, data.get("tool", "XSS HUNTER")
    except Exception as e:
        print(f"{error} Gagal membaca file payload: {e}")
        return [], "XSS HUNTER"

# Ambil semua form dari halaman
def extract_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"{error} Gagal mengambil form dari {url}: {e}")
        return []

# Ambil detail dari form
def get_form_details(form):
    inputs = []
    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.get("name")
        if name:
            inputs.append({"name": name, "type": tag.get("type", "text")})
    return {
        "action": form.get("action"),
        "method": form.get("method", "get").lower(),
        "inputs": inputs
    }

# Kirim form
def submit_form(details, base_url, payload):
    target_url = urljoin(base_url, details["action"]) if details["action"] else base_url
    data = {field["name"]: payload for field in details["inputs"] if field["type"] != "submit"}

    try:
        if details["method"] == "post":
            r = requests.post(target_url, data=data, timeout=10)
            return r, f"{target_url} [POST]"
        else:
            r = requests.get(target_url, params=data, timeout=10)
            full_url = requests.Request('GET', target_url, params=data).prepare().url
            return r, f"{full_url} [GET]"
    except Exception as e:
        return None, f"{error} Gagal mengirim request: {e}"

# Validasi apakah payload benar-benar tidak di-escape
def payload_found(payload, response_text):
    # Jangan anggap payload berhasil jika di-escape atau ditampilkan sebagai teks
    if payload in response_text:
        if escape(payload) in response_text:
            return False  # Payload ditampilkan sebagai teks
        if "&lt;" in response_text or "&gt;" in response_text:
            return False  # Ada indikasi payload diubah jadi karakter aman
        return True
    elif quote(payload) in response_text:
        return True  # Payload masuk sebagai URL-encoded (masih bisa jadi vuln)
    return False

# Fungsi utama yang akan dipanggil dari main.py
def run_scanner(target_url, pt_limit=None):
    secret = load_secret_config()
    payloads, tool_name = load_payloads("payloads.json", pt_limit)
    forms = extract_forms(target_url)

    print(f"\n{info} Tools     : {tool_name}")
    print(f"{info} Target    : {target_url}")
    print(f"{info} Form ditemukan : {len(forms)}\n")

    if not forms:
        print(f"{warning} Tidak ada form ditemukan.")
        return

    for idx, form in enumerate(forms, start=1):
        print(f"{info} ─── Form #{idx}")
        details = get_form_details(form)
        print(f"     Method : {details['method'].upper()}")
        print(f"     Action : {details['action'] or '[default URL]'}")
        print(f"     Fields : {[f['name'] for f in details['inputs']]}")

        success_count = 0
        total = len(payloads)

        for p in payloads:
            res, test_url = submit_form(details, target_url, p)
            if res and payload_found(p, res.text):
                color_url = url_vuln + test_url + Style.RESET_ALL
                method_color = get_ok + "[GET]" + Style.RESET_ALL if "[GET]" in test_url else "[POST]"
                print(f"  {success} XSS TERDETEKSI → {color_url} {method_color}")
                success_count += 1
            else:
                print(f"  {warning} Payload gagal: {p}")

        if success_count == total:
            print(f"\n  {success} SEMUA ({total}/{total}) PAYLOAD MATCH → FORM INI 100% VULNERABLE\n")
        else:
            print(f"\n  {warning} {success_count}/{total} payload berhasil. Form kemungkinan sebagian rentan.\n")
