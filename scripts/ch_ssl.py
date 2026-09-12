#!/usr/bin/env python3
"""
Простой чекер рус SSL-сертификатов.
Умеет смотреть на российские сертификаты (Минцифры) - обычные чекеры их не видят,
потому что корневого сертификата нет в стандартном хранилище.

Запуск:
    python check_ssl.py --file domains.txt --days 30
    python check_ssl.py --domain ya.ru --days 30
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# --- настройки ---

# тут сертификаты Минцифры
CERTS_DIR = Path(__file__).parent / "certs"
ROOT_CA = CERTS_DIR / "russian_trusted_root_ca_pem.crt"

# уведомление в TG
TG_TOKEN = None 
TG_CHAT_ID = None

TIMEOUT = 10  


def load_env():
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k == "TG_TOKEN":
            global TG_TOKEN
            TG_TOKEN = v
        elif k == "TG_CHAT_ID":
            global TG_CHAT_ID
            TG_CHAT_ID = v


def make_ssl_context():
    ctx = ssl.create_default_context()
    if ROOT_CA.exists():
        try:
            ctx.load_verify_locations(cafile=str(ROOT_CA))
        except Exception as e:
            print(f"[!] не смог загрузить {ROOT_CA}: {e}")
    else:
        print(f"[!] нет файла {ROOT_CA}, российские сертификаты могут не проверяться")
    return ctx


def get_cert(host, port=443):
    ctx = make_ssl_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except ssl.SSLCertVerificationError as e:
        # отдельно ловим проблему с цепочкой - часто из-за того же Минцифры
        print(f"[!] {host}: ошибка проверки сертификата: {e}")
        return None
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        print(f"[!] {host}: не смог подключиться: {e}")
        return None
    except Exception as e:
        print(f"[!] {host}: непонятная ошибка: {e}")
        return None


def parse_date(s):
    s = s.replace(" GMT", "").strip()
    return datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)


def is_russian_cert(cert):
    issuer = dict(x[0] for x in cert.get("issuer", []))
    cn = issuer.get("commonName", "")
    return "Russian Trusted" in cn


def days_left(expiry):
    now = datetime.now(timezone.utc)
    delta = expiry - now
    return delta.days


def send_telegram(msg):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": msg}, timeout=10)
        if r.status_code != 200:
            print(f"[!] телега ответила {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[!] не смог отправить в телегу: {e}")


def check_domain(domain, threshold):
    print(f"\n=== {domain} ===")
    cert = get_cert(domain)
    if not cert:
        return False

    try:
        expiry = parse_date(cert["notAfter"])
    except Exception as e:
        print(f"[!] {domain}: {e}")
        return False

    left = days_left(expiry)
    ru = is_russian_cert(cert)

    tag = "🇷🇺" if ru else "World"
    print(f"  выдан: {tag} {'Минцифры' if ru else 'иностранный УЦ'}")
    print(f"  истекает: {expiry.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  осталось: {left} дн.")

    if left < 0:
        msg = f"X {domain}: сертификат ПРОСРОЧЕН!"
        print(msg)
        send_telegram(msg)
        return False
    elif left <= threshold:
        msg = f"ALLARM {domain}: сертификат истекает через {left} дн. {'(Минцифры)' if ru else ''}"
        print(msg)
        send_telegram(msg)
        return False
    else:
        print("  OK")
        return True


def main():
    parser = argparse.ArgumentParser(description="SSL certificate checker")
    parser.add_argument("--domain", help="один домен")
    parser.add_argument("--file", help="файл со списком доменов (по одному в строке)")
    parser.add_argument("--days", type=int, default=30, help="за сколько дней предупреждать")
    args = parser.parse_args()

    if not args.domain and not args.file:
        print("укажи --domain или --file")
        sys.exit(1)

    load_env()

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"нет файла {p}")
            sys.exit(1)
        # читаем, игнорим пустые строки и комменты
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)

    print(f"проверяю {len(domains)} домен(ов), порог {args.days} дней")

    bad = 0
    for d in domains:
        if not check_domain(d, args.days):
            bad += 1

    print(f"\nитог: проблемных - {bad} из {len(domains)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
