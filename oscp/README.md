# OSCP 치트시트

heretek.dev OSCP Cheatsheet(Jean Romero)를 재구성한 시험 대비 문서 모음이다. 파일명 = 주제이며 각 문서는 명령·체크리스트 중심으로 배치했다.

> 출처: https://heretek.dev/oscp-cheatsheet/ (Jean Romero) — 개인 학습용 재구성본. 원문의 명령과 기법을 전부 옮기고 표는 목록으로 바꿨다.

- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 방법론·전략

- [methodology.md](methodology.md) — 시험 당일 전체 흐름 마스터 체크리스트 (PHASE 0~7 + 긴급 대응표)
- [exam-strategy.md](exam-strategy.md) — 시험 형식·시간 배분·통과 조합
- [report-writing.md](report-writing.md) — 리포트 작성

## 열거·초기 침투

- [enumeration.md](enumeration.md) — 포트별 열거 명령 전체
- [web-attacks.md](web-attacks.md) — 웹 정찰부터 취약점 테스트까지
- [sql-injection.md](sql-injection.md) — SQLi 페이로드 (MySQL·MSSQL·Postgres·SQLite)
- [client-side-attacks.md](client-side-attacks.md) — 클라이언트 사이드 공격
- [buffer-overflows.md](buffer-overflows.md) — 버퍼 오버플로 & 익스플로잇 수정 워크플로

## 쉘·권한 상승

- [shells-and-transfers.md](shells-and-transfers.md) — 리버스 쉘 & 파일 전송
- [linux-privilege-escalation.md](linux-privilege-escalation.md) — Linux 권한 상승
- [windows-privilege-escalation.md](windows-privilege-escalation.md) — Windows 권한 상승
- [post-exploitation.md](post-exploitation.md) — 후속 공격·creds 수확·스프레이

## Active Directory·피벗

- [active-directory-playbook.md](active-directory-playbook.md) — AD 단계별 플레이북
- [active-directory-tools.md](active-directory-tools.md) — AD 도구 명령 모음
- [pivoting-and-tunneling.md](pivoting-and-tunneling.md) — chisel·ssh·socat 피벗 & 터널링
- [ligolo-ng.md](ligolo-ng.md) — ligolo-ng 터널링

## 패스워드·지원

- [password-attacks.md](password-attacks.md) — 패스워드 공격
- [hash-types.md](hash-types.md) — 해시 유형별 hashcat·john 모드
- [av-evasion.md](av-evasion.md) — AV 우회
- [cross-compiling.md](cross-compiling.md) — 크로스 컴파일
