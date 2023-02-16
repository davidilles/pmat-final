
## File type
```
C:\Users\analyst\Desktop
λ file Ransomware.wannacry.exe
Ransomware.wannacry.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

## File hash
```
PS C:\Users\analyst\Desktop> Get-FileHash .\Ransomware.wannacry.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C       C:\Users\analyst\Desktop\Ransomware.wannacry.exe
```

## Virustotal 

### Hitrate

![[Pasted image 20230216222949.png]]

### Basic details
![[Pasted image 20230216223106.png]]

## Floss 

### Run
```
C:\Users\analyst\Desktop
λ FLOSS.exe Ransomware.wannacry.exe > floss_results.txt
INFO: floss: extracting static strings...
finding decoding function features: 100%|███████████████████████████████████████| 87/87 [00:00<00:00, 792.20 functions/s, skipped 4 library functions (4%)] INFO: floss.stackstrings: extracting stackstrings from 55 functions
INFO: floss.results: SMBu
INFO: floss.results: /K__USERID__PLACEHOLDER__
INFO: floss.results: __TREEPATH_REPLACE__
INFO: floss.results: PIPE
INFO: floss.results: SMBr
INFO: floss.results: PC NETWORK PROGRAM 1.0
INFO: floss.results: LANMAN1.0
INFO: floss.results: Windows for Workgroups 3.1a
INFO: floss.results: LM1.2X002
INFO: floss.results: LANMAN2.1
INFO: floss.results: NT LM 0.12
INFO: floss.results: SMBs
INFO: floss.results: SMB2
INFO: floss.results: Windows 2000 2195
INFO: floss.results: Windows 2000 5.0
INFO: floss.results: \192.168.56.20\IPC$
INFO: floss.results: http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
extracting stackstrings: 100%|█████████████████████████████████████████████████████████████████████████████████████| 55/55 [01:29<00:00,  1.63s/ functions] INFO: floss.tightstrings: extracting tightstrings from 6 functions...
extracting tightstrings from function 0x409750: 100%|████████████████████████████████████████████████████████████████| 6/6 [00:00<00:00, 17.39 functions/s] INFO: floss.string_decoder: decoding strings
INFO: floss.results: SMBu
INFO: floss.results: __TREEPATH_REPLACE__
INFO: floss.results: AWAVAUATSQRUWVPP
INFO: floss.results: QQjh
INFO: floss.results: t.M1
INFO: floss.results: XX^_]ZY[A\A]A^A_H
INFO: floss.results: SVQRH
emulating function 0x408a10 (call 2/2): 100%|██████████████████████████████████████████████████████████████████████| 21/21 [00:35<00:00,  1.69s/ functions] INFO: floss: finished execution after 162.61 seconds
```

### Results

### Stack strings

```
----------------------------
| FLOSS STACK STRINGS (17) |
----------------------------
SMBu
/K__USERID__PLACEHOLDER__
__TREEPATH_REPLACE__
PIPE
SMBr
PC NETWORK PROGRAM 1.0
LANMAN1.0
Windows for Workgroups 3.1a
LM1.2X002
LANMAN2.1
NT LM 0.12
SMBs
SMB2
Windows 2000 2195
Windows 2000 5.0
\192.168.56.20\IPC$
http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
```

### Handpicked strings
```
Microsoft Enhanced RSA and AES Cryptographic Provider
CryptGenKey
CryptDecrypt
CryptEncrypt
CryptDestroyKey
CryptImportKey
CryptAcquireContextA
cmd.exe /c "%s"
115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn
12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
%s%d
Global\MsWinZonesCacheCounterMutexA
tasksche.exe
TaskStart
t.wnry
icacls . /grant Everyone:F /T /C /Q
attrib +h .
WNcry@2ol7
```

```
Microsoft Base Cryptographic Provider v1.0
%d.%d.%d.%d
mssecsvc2.0
Microsoft Security Center (2.0) Service
%s -m security
C:\%s\qeriuwjhrf
C:\%s\%s
WINDOWS
tasksche.exe
CloseHandle
WriteFile
CreateFileA
CreateProcessA
http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
!This program cannot be run in DOS mode.
```

## PE Analysis

### Virtual vs Raw sizes

![[Pasted image 20230216224319.png]]

![[Pasted image 20230216224334.png]]

![[Pasted image 20230216224348.png]]

![[Pasted image 20230216224415.png]]

### Import address table

![[Pasted image 20230216224845.png]]

![[Pasted image 20230216224901.png]]

![[Pasted image 20230216225002.png]]

![[../_images/Pasted image 20230216225758.png]]