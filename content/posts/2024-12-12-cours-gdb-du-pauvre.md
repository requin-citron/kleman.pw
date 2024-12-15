---
title: Cours GDB du pauvre
tag: Reverse
date: '2024-12-12'
---

**_On essaye d'apprendre des trucs ouuuuuuuuuuuuuuuuuuuu_**

# Installation de la caisse à outils

Pour tirer pleinement parti de GDB, il est utile d’avoir un écosystème complet d’outils et de dépendances, notamment pour la compilation, l’inspection des binaires, la visualisation mémoire, etc.

## GDB

Ce cours étant consacré à **GDB**, l’outil essentiel dont vous avez besoin est naturellement **GDB** lui-même. GDB est le débogueur standard sous Linux pour les programmes natifs.

```
# Debian/Ubuntu
apt-get install gdb

# Arch Linux
pacman -S gdb
```

### Usage

```
gdb ./program    # debug process
gdb -p pid       #debug running program with specifique pid
gdb -n ./program #désactive gdbinit
```

## Outils de compilation et symboles de débogage

Outils de compilation pour la compilation programes.


```
# Debian/Ubuntu
apt-get install build-essential

# Arch Linux
pacman -S build-essential
```

### Usage

```
gcc program.c -o program                         # compilation standard
gcc program.c -o program -Wall -Wextra -pedantic # mode difficile
gcc program.c -o program -ggdb                   # compile with gdb debug
```

## GEF 

Une surcouche destinée à rendre l’utilisation de GDB plus intuitive.

```
$ wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

# Utilisation de GDB

## Commandes initiales utiles

```
run    # demarre le programme
starti # demarre le programme et break a la première instruction
```

## Affichage et navigation

```
disass             # affichage du code assembleur
list               # affichage du code en c
set listsize count # change number of lines show by list
x/30i 0xaddresse   # disassemble 30 instruction from 0xaddresse

stepi              # prochaine instruction en assembleur
nexti              # prochaine instruction en assembleur (ne rentre pas dans les boucles)

step               # prochaine instruction en c
next               # prochaine instruction en c (ne rentre pas dans les boucles)
```

## Breakpoint

```
break main                  # break sur main
break *0xaddress            # break sur l'instruction pointé par l'addresse
break *0xaddress if $eax=12 # break sur l'instruction pointé par l'addresse avec condition

watch  *(int *)0x600850
rwatch *(int *)0x600850
awatch *(int *)0x600850 

continue                    # continue l'éxecution du programme
```

## Affichage

```
print variable    # affiche le contenue de la variable
print $rax        # affiche le contenue du registre rax

x/x 0xaddresse    # affiche la contenue a l'addresse addresse 
info registers    # affiche les registres
```

## Appel de fonction

```
call (int)system("id")
jump *0xaddresse
```