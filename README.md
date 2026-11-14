# agnusdei207 — OSCP Cheatsheet

OSCP 준비를 위한 치트시트, 방법론, 도구 모음. [heretek.dev/oscp-cheatsheet](https://heretek.dev/oscp-cheatsheet/) 디자인(Hugo + PaperMod)을 그대로 가져와 한국어로 정리했다.

## 구조

| 경로 | 내용 |
|---|---|
| `content/oscp-cheatsheet/` | OSCP 치트시트 (~20개 주제) |
| `content/methodology/` | AD 공격 방법론, 열거 워크플로 |
| `content/tools/` | BloodHound, Impacket 가이드 |

## 빌드

```bash
hugo --gc --minify
```

## 배포

`main` 브랜치 푸시 시 GitHub Actions 가 자동으로 GitHub Pages 에 배포한다.