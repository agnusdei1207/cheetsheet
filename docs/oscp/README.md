# OSCP Cheatsheet

Exam preparation document collection reconstructed from hererek.dev OSCP Cheatsheet (Jean Romero). File names = topic. Each document is command/checklist-focused.

> Source: https://hererek.dev/oscp-cheatsheet/ (Jean Romero) — Personal study reconstruction. All original commands and techniques are reproduced; tables converted to lists.

- Variables: `$TARGET` = target, `$KALI` = attacker (Kali) IP

## Methodology & Strategy

- [methodology.md](methodology.md) — Master checklist of the full exam day flow (PHASE 0-7 + emergency response table)
- [exam-strategy.md](exam-strategy.md) — Exam format, time allocation, passing combinations
- [report-writing.md](report-writing.md) — Report writing

## Enumeration & Initial Access

- [enumeration.md](enumeration.md) — Full port-by-port enumeration commands
- [web-attacks.md](web-attacks.md) — Web reconnaissance to vulnerability testing
- [sql-injection.md](sql-injection.md) — SQLi payloads (MySQL, MSSQL, Postgres, SQLite)
- [client-side-attacks.md](client-side-attacks.md) — Client-side attacks
- [buffer-overflows.md](buffer-overflows.md) — Buffer overflows & exploit fixing workflow

## Shells & Privilege Escalation

- [shells-and-transfers.md](shells-and-transfers.md) — Reverse shells & file transfers
- [linux-privilege-escalation.md](linux-privilege-escalation.md) — Linux privilege escalation
- [windows-privilege-escalation.md](windows-privilege-escalation.md) — Windows privilege escalation
- [post-exploitation.md](post-exploitation.md) — Post-exploitation, credential harvesting, spraying

## Active Directory & Pivoting

- [active-directory-playbook.md](active-directory-playbook.md) — AD step-by-step playbook
- [active-directory-tools.md](active-directory-tools.md) — AD tool command collection
- [pivoting-and-tunneling.md](pivoting-and-tunneling.md) — chisel, ssh, socat pivoting & tunneling
- [ligolo-ng.md](ligolo-ng.md) — ligolo-ng tunneling

## Password & Support

- [password-attacks.md](password-attacks.md) — Password attacks
- [hash-types.md](hash-types.md) — Hashcat & John modes by hash type
- [av-evasion.md](av-evasion.md) — AV evasion
- [cross-compiling.md](cross-compiling.md) — Cross-compiling
