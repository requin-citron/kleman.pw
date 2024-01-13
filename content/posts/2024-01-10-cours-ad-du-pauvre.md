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

# Windows

## Shares

```bash

```

### smbclient

```
smbclient -N -L \\\\ip
smbclient -N \\\\ip\\Share
smbclient -U 'User%Password' \\\\ip\\Share
```

### mount

```
mount -t cifs //ip/Name /point/de/montage/
mount -t cifs -o username=crz,password=TonWifiEstNull //ip/Name /point/de/montage/
```

### nxc

```
nxc smb ip
nxc smb ip -u 'user' -p 'password'
```

### windows

```
net share
net use Z: \\computer_name\share_name
```

## Services

### windows

```
sc query     # cmd.exe
Get-Service  # powershell.exe

services.msc
```

# Lab

```
Administrator : fe63693e9e.2e90861a9c
antoine       : 099bd3d1c39.c22d1a464
srv_klemou    : 634daa6f9.4519be0b91c
```


```
10.10.10.10-20 # serveur
10.10.10.20-30 # machine utilisateur
```

