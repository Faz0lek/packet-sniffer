## IPK - Projekt 2 - Sniffer paketů

Autor: Martin Kostelník (xkoste12@stud.fit.vutbr.cz)

Datum: 3.5.2020

---

### Popis implementace

Program pracuje jako sniffer paketů. Sleduje zadané rozhraní a analyzuje příchozí a odchozí pakety, které následně vypíše na standardní výstup. Projekt je implementován v jazyce C++ za použití knihovny pcap a síťové knihovny BSD sockets.

### Argumenty

Nápověda se vypíše při použití argumentu `-h/--help` a nebo při zakázané kombinaci argumentů či při neznámém argumentu. Pokud byl použit argument `-h/--help`, končí program s návratovým kódem 0. Při chybě končí s návratovým kódem 1.

Malá změnu oproti zadání je, že v mé implementaci není povoleno použít -t a -u parametry zároveň. Při pokusu o použití obou je vypsána nápověda a program skončí. Rozhodl jsem se tak na základě věty ze zadání, a to: „-t nebo --tcp (bude zobrazovat pouze tcp pakety)“. Přišlo mi logické, že pokud -t zobrazuje pouze tcp pakety, potom je nesmyslné jej kombinovat s parametrem -u.

### Překlad
Projekt se dá přeložit příkazem `make`

Kromě cíle pro překlad obsahuje Makefile i cíle následující:
- clean - smaže soubory vzniklé za předkalu
- pack - zabalí projekt programem tar k odevzdání

### Příklad spuštění

`sudo ./proj2 -i eth0 -t -n 20`

### Odevzdané soubory

- main.cpp - zdrojový kód
- Makefile - soubor pro překlad
- manual.pdf - dokumentace
- README.md - krátký popis řešení
