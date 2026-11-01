---
title: "Hack The Box Bombs Landed CTF Detaylı Writeup"
published: 2024-02-23
author: balpars
draft: false
tags: ['ctf', 'reverse_engineering']
description: "Hack The Box | Bombs Landed tersine mühendislik CTF'inin detaylı writeup'ı"
slug: hack-the-box-bombs-landed-writeup
toc: true
series: 'Reverse Engineering'
---

## \_start: 

![32-bit BombsLanded binary'sinde pwndbg checksec çıktısı: No RELRO, stack canary yok, NX bilinmiyor ve 0x8048000 adresinde No PIE.](./pwndbg-checksec-binary-protections.png)

checksec ile baktığımızda PIE'ın kapalı olduğunu görüyoruz. Adres offset'leri aynı kalacağı için disassembler ile debugger'ı yan yana kullanmak kolaylaşacak. Elimizde 32-bit bir binary var.

Global Offset Table da bozulmuş, bu da debug etmeyi zorlaştıracak.

![BombsLanded Bad luck dude yazıyor; ltrace .dynsym'i bulamıyor, strings ise dlsym ve strncmp gibi import'ları listelemeye başlıyor.](./bombslanded-run-ltrace-fails.png)

Programı çalıştırınca en ufak bir ipucu bile vermiyor. Ltrace de çalışmıyor; bu da dosyanın statik linklendiğini düşündürüyor, ama birazdan öyle olmadığını göreceğiz.

![ptrace'in de göründüğü strings çıktısı; input password, Correct password ve Bad luck dude mesajları işaretlenmiş.](./strings-ptrace-password-messages.png)

Dikkat çekici birkaç string var. Aralarında debugger'ların bir process'e attach olmak için kullandığı ptrace de var, yani anti-debugging amaçlı kontrolleri bypass etmemiz gerekebilir. Ama bu binary'de hiçbir şey yapmam gerekmedi.

## Tersine Mühendislik 

![Ghidra'da decompile edilmiş main; param_1 kontrolü, mmap, 0xc3 ile memset, unpack döngüleri ve memory_addres çağrısı numaralı oklarla gösterilmiş.](./ghidra-main-mmap-unpacking.png)

1. Program, 4'ten az komut satırı argümanı verilip verilmediğine bakıyor ve daha önce hazırladığı iki değişkeni karşılaştırıyor. C'de main fonksiyonunun ilk parametresi argüman sayısıdır.
2. İlk olarak mmap çağrılıyor; mmap, ayırdığı bellek bölgesinin başlangıç adresini gösteren bir pointer döndürür. Değişkenin adını memory_address yaptım, kod bir anda çok daha okunur hale geldi.
3. Ardından memset, mmap'in ayırdığı buffer'ı `0xc3` ile dolduruyor. Bu da (malum bir yapay zekâya göre) x86 assembly'de `RET` instruction'ının opcode'u.
4. memory_address değişkenini takip edince, gösterdiği adrese bazı veriler yazıldığını görüyoruz.
5. Sonra da memory_address çağrılıyor. Demek ki yukarıdaki kod, memory_address'in gösterdiği bellek bölgesine bir fonksiyon unpack etmiş.

O bellek bölgesinde ne olduğunu bilmediğimiz için burada yapabileceğimiz başka bir şey yok. Devam etmek için debugger'a geçmemiz gerekiyor.

Ghidra'dan çıkmadan önce diğer fonksiyonlara da göz atmakta fayda var; içlerinden biri dikkatimizi çekmeli: strncmp fonksiyonu.

![Ghidra Symbol Tree'de main'in altında seçili strncmp fonksiyonu ve birkaç FUN_ fonksiyonu.](./ghidra-symbol-tree-strncmp.png)

![Ghidra listing'i ve decompile edilmiş strncmp; s2'yi 10 ile XOR'layan while döngüsünü kontrol eden 0x08048b66 adresindeki JA okla işaretlenmiş.](./ghidra-strncmp-while-loop.png)

Bunun C'deki bildiğimiz strncmp fonksiyonuyla pek alakası yok. İçinde ilginç bir while döngüsü var; bir string oluşturuyor gibi, büyük ihtimalle de parolayı. Debugger'da daha yakından bakmak için döngü koşulunun offset'ini not alıyoruz.

Şimdilik bu fonksiyonu çağıran bir yer görünmüyor. Bu da, çağrılacaksa çağrının dinamik olarak çözümleneceği anlamına geliyor.

## Debugging 

Başta koymaya değer birkaç breakpoint:

![Ghidra listing'inde 0x080489ba adresindeki JA ve 0x080489bf adresindeki JG, yanında da param_1'in 4'ten büyük olup olmadığını kontrol eden decompile edilmiş if ifadesi.](./ghidra-argument-check-jumps.png)

- if ifadesinin ilk koşulu.
- if'i bypass etmek için aynı ifadenin ikinci koşulu.
- strncmp'deki while döngüsü; bize parolayı ele verebilir.

Bu breakpoint'ler parolayı bulmaya yetmezse memory_address çağrısına da breakpoint koyup step-into yapmamız gerekebilir.

![Ghidra'da 0x08048aba adresindeki CALL memory_addres, yani mmap bölgesine dinamik olarak yazılan fonksiyonun çağrısı.](./ghidra-call-unpacked-function.png)

![pwndbg'de 0x080489ba, 0x080489bf ve 0x08048b66 adreslerine breakpoint konuyor; info functions ise tanımlı tek bir fonksiyon bile göstermiyor.](./pwndbg-breakpoints-info-functions.png)

Fonksiyon isimleri tabii ki yok.

![pwndbg 0x80489ba adresindeki ja'da durmuş; EFLAGS register'ının 6. bitini set edince zero flag açılıyor.](./pwndbg-set-zero-flag.png)

İlk kontrol bir JA; bunu bypass etmek için ZF'yi set etmemiz gerekiyor. İkinci kontrol olan JG'de de sign flag'i tersine çevirmek yetiyor, böylece iki kontrolü de geçiyoruz. gdb ve koşullu jump'larla ilgili daha fazla bilgi için aşağıya birkaç kaynak bırakıyorum.

[https://cheatography.com/superkojiman/cheat-sheets/gdb-pwndbg/](https://cheatography.com/superkojiman/cheat-sheets/gdb-pwndbg/)

[https://www.philadelphia.edu.jo/academics/qhamarsheh/uploads/Lecture 18 Conditional Jumps Instructions.pdf](https://www.philadelphia.edu.jo/academics/qhamarsheh/uploads/Lecture%2018%20Conditional%20Jumps%20Instructions.pdf)

Program bizden parola istiyor. Herhangi bir şey girince, tahmin ettiğimiz gibi üçüncü breakpoint'e düşüyoruz. Devam edip art arda enter'a bastıkça parolanın stack'te adım adım oluştuğunu görüyoruz.

![pwndbg, strncmp döngüsündeki 0x8048b66 breakpoint'inde durmuş; oklar ja'yı ve stack'te oluşan parolayı gösteriyor (parola sansürlenmiş).](./pwndbg-password-built-on-stack.png)

1. Üçüncü breakpoint'e düştük.
2. Stack'te bir string oluşturuluyor.

Son olarak bulduğumuz parolayı deniyoruz. İlk kontrolü geçmek için binary'yi 4'ten fazla argümanla çalıştırmamız gerekiyor. Aslında 4 argüman da yeterdi, çünkü C'de main fonksiyonunun ilk argümanı programın adıdır.

![BombsLanded beş argümanla çalıştırılınca parolayı (sansürlü) kabul edip you win yazıyor.](./bombslanded-correct-password-win.png)

Kazandık…
