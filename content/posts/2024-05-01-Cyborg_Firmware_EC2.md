---
title: Writeup Cyborg Firmware EC2
tag: Reverse
date: '2024-05-01'
---

# Reverse cyborg firmware

## TLDR;

sadmiaou

## Analyse

Ce chanllenge est proposé dans le cadre de l'EC2 et est composée de 2 fichier decode-me et generator ainsi que la présentation du flag.
`decode-me` est un simple password checker et ce suffit à lui même, quand à lui le fichier `generator` n'est pas util à la résolution du chall.


L'enoncé du chall donne une information crutial aka le debut du flag `MALICE{`.

## Reverse

La fonction main commence directement par une technique d'anti débug, pour ce faire le développeur hook ca fonction a un signal puis le trigger pour démarer la charge utile du programme.

![](/img/Cyborg_Firmware/cyborg_firmware_1.png)

Pour bypass cette protection il est possible de positionner un breakpoint sur la fonction signal et jump manuellement sur `authentification` et ainsi éviter de modifier le handler du signal.

La deuxième contre mesure déployé par le développeur consiste à vérifier la présence d'un débuger. Dans le cas échant le programme change son coportement il est donc primordiale de trouver une solution pour pouvoir utiliser GDB.

![](/img/Cyborg_Firmware/cyborg_firmware_2.png)

En rouge la présense du débuger est vérifier via un appel à ptrace. Le cas écheant la fonction `check_password2`. Dans notre cas nous voulons appeller `check_password` (fonction en vert) pour obtenir le message de succés.

Le bypass est simple il suffit de positionner un breakpoint aprés l'appel de ptrace et modifier le registre contenant le retour de la fonction aka (eax).

Le bloc rouge représente le flag encodé en mémoire, il faut donc trouver un moyen d'inverser le processus. La chaine fait 35 octets en mémoire un bruteforce bêtes et méchant n'est donc pas envisagable.

![](/img/Cyborg_Firmware/cyborg_firmware_3.png)

La fonction genTab détailler si dessous est crutial pour la résolution du problème. L'entrée utilisateur (mot de passe) est utilisé comme seed pour initialiser l'aléatoire du programme. Cependant un modulo est utilisé (mal décompiler par ghidra) il y a donc 1024 seed différentes. Ensuite l'aléatoire dériver de cette seed est utilisé pour initialiser un tableau de valeur aléatoire (ascii)

![](/img/Cyborg_Firmware/cyborg_firmware_4.png)

Le bloc bleu représente une boucle sur chaque éléments de notre entrée utilisateur qui passe dans une fonction sélectionné depuis une vtable contenant 4 fonctions `f1,f2,f3,f4` le charactère encodé est utilisé pour récupérer la fonction suivante il est donc à noter que chaque caractère dépend du précédent. De l'index initial est choisie en fonction du premié caractère du mot de passe.

Une rétro static n'est pas possible au vue de mon niveau j'ai donc utiliser GDB en patchant les points d'anti debug pour comprendre en détaille le bloc bleu.

![](/img/Cyborg_Firmware/cyborg_firmware_5.png)
![](/img/Cyborg_Firmware/cyborg_firmware_6.png)
![](/img/Cyborg_Firmware/cyborg_firmware_7.png)
![](/img/Cyborg_Firmware/cyborg_firmware_8.png)

Les quatres fonctions de la vtable utilise les valeurs précédament calculer dans `genTab` de plus quatres autres fonction sont utilisé pour faire des modification sur les paramètres.
Via un vérification sur GDB les paramètres passé sont le charactère a encodé ainsi que son index.


![](/img/Cyborg_Firmware/cyborg_firmware_9.png)
![](/img/Cyborg_Firmware/cyborg_firmware_10.png)
![](/img/Cyborg_Firmware/cyborg_firmware_11.png)
![](/img/Cyborg_Firmware/cyborg_firmware_12.png)

Il est important de remarquer que les fonctions `f6,f7` ne sont pas réversible à cause du shift qui entraine une perte d'information sur les bits.

## Résumé de la situation

Nous avons un flag checker qui utilise l'entrée utilisateur pour générer une seed entre 0 et 1023 qui sera utiliser pour générer un tableau de paramètre utiliser pour modifier le comportement de nos fonction d'encodage. De plus l'index initial de la vtable dépend du premier caractère. Chaque caractère ajouté ou modifier du flag entraine un changement de la seed qui entraine un changement des fonctions qui entraine un changement complet du password encodé.


## Cook

Pour le moment si nous voulons bruteforcer le flag caractères par caractère nous avons 1024 seed différente + 4 index possible pour la première fonction et à cela il faut rajouter les différentes possibilité de caractère.

Nous alons donc partir d'un autres postula premièrement nous savont que le flag commence par `MALICE{` il est donc possible de déterminer l'index de la vtable. Cependant il nous manque toujours la seed pour paramétrer correctement nos fonctions. Pour cela nous allons bruteforce dans un premier temps toutes les seed possible et essayer de voir combien match les 7 premier caractères encodé.

Le binaire étant static j'ai du réimplémenter les 8 fonctions à la main en C.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

char ascii[0x60] = {0};

int f8(int param_1)
{
  return ~param_1;
}

uint f7(int param_1,int param_2)
{
  return param_1 >> ((8 - param_2) & 0x1f) | param_1 << (param_2 & 0x1f);
}

uint f6(int param_1,int param_2)
{
  return param_1 << ((8 - param_2) & 0x1f) | param_1 >> (param_2 & 0x1f);
}


int f5(int param_1,int param_2)
{
  return param_1 ^ param_2;
}

int f1(int param_1, int index){
    int tmp = ascii[index];
    int retf7 = f7(tmp&0xff, 3);
    return f5(param_1,retf7)&0xff;
}

int f2(int param_1,int param_2){
    int retf5 = f5(ascii[param_2] ,param_1 )&0xff;
    return f6(retf5,1)&0xff;
}

int f3(int inv,int index){
  int retf6 = f6(ascii[index]&0xff,3);
  int retf8 = f8((int)inv);
  return f7(retf8&0xff , ((retf6&0xff) % 8) & 0xff );
}

int f4(int param_1,int param_2){
  return f8(f5(param_1,param_2));
}

void gen_tab(int seed, char *tab, size_t len){ // gen ascii from specifique seed
    srandom(seed & 0x3ff);
    for(size_t i=0;i<len;i++){
        tab[i] = rand();
    }
}

int call_func(int index, int param1, int param2){ // vtable simulation
    if((index%4) == 0 ){
        return f1(param1, param2);
    }else if((index%4) == 1){
        return f2(param1, param2);
    }else if((index%4) == 2){
        return f3(param1, param2);
    }else if((index%4) == 3){
        return f4(param1, param2);
    }
    
    return -1; // never ritch
}

char* compute_flag(char *user_input){
    int last = 1; // hardcode vtable index get from GDB

    char *encoded_input = malloc(sizeof(char)*strlen(user_input));

    if(encoded_input == NULL){
        printf("Alloc failed\n");
        exit(1);
    }

    for(size_t i=0;i<strlen(user_input); i++){
        last =call_func(last, (int)user_input[i], (int)i)&0xff;
        encoded_input[i] = last;
    }
    return encoded_input;
}


int bruteforce_seed(char* know_text, unsigned char* encoded_flag){
    char* encoded_input = NULL;
    int seed=-1;

    for(int s=0;s<1024;s++){
        gen_tab(s, ascii, 0x60); // generate ascii random tab with specifique seed
        encoded_input = compute_flag(know_text);
        if(memcmp(encoded_input, encoded_flag, strlen(know_text)) == 0){ // compare first bytes are equals
            printf("[+] seed FOUND %d\n",s);
            seed = s;
        }
    }
    return seed;
}



int main(int argc, char **argv){


    unsigned char encoded_flag[35] = {0x93,0xbf,0xb1,0x3f,0xb8,0x30,0x68,0x3c ,0xae,0xdf,0x6c,0x3b,0x96,0x28,0xc0,0xfd ,0xdb,0x80,0x8d,0x90,0x12,0xb1,0x8c,0x74 ,0x6b,0x87,0x91,0x52,0x37,0xc3,0xdb,0xcd ,0x04,0xa3,0x00};
    char flag[35] = {0};
    strcat(flag, "MALICE{");

    int seed = bruteforce_seed(flag, encoded_flag);
    char* encoded_input = NULL;

    bool valide_char = false; 

    gen_tab(seed, ascii, 0x60); // generation du bon tableau
    for(size_t i=strlen(flag);i<35;i++){
        for(char c=0;c<=256;c++){

            flag[i] = c;

            encoded_input = compute_flag(flag);
            valide_char = memcmp(encoded_input, encoded_flag, i+1);
            free(encoded_input);
            
            if(valide_char == 0){
                break;
            }
        }
    }
    printf("[+] FLAG %s\n", flag);

    return 0;
}
```

Par chance uniquement 1 seed fonctionne avec notre situation. Il ne nous reste plus qu'a bruteforce caractère par caractère et ainsi afficher le flag.