---
title: "Anahtar Diffie-Hellman'dan"
slug: diffie-hellman-key-exchange
author: balpars
published: 2024-03-02
draft: false
tags: ['cryptography']
description: "Diffie-Hellman anahtar değişimiyle güvensiz kanallarda güvenli iletişim"
toc: true
series: 'Cryptography Basics' 
---

## Motivasyon... 

Eski çağlardan bu yana güvenli iletişimin temel yolu hep şifreleme olmuştur.

Ama ortada büyük bir sorun var. Karşı tarafın mesajımızı çözebilmesi için
anahtarı onunla da paylaşmamız gerekiyor. Peki bu anahtarı güvenli bir şekilde nasıl paylaşacağız?

Daha resmî bir dille söylemek gerekirse, derdimiz önceden paylaşılmış hiçbir sır olmadan güvensiz kanallar üzerinden güvenli iletişim kurmak.

Diffie-Hellman algoritması sayesinde iki taraf, birilerinin dinlediği açık ağlarda bile ortak bir gizli anahtarda anlaşabilir.

Diffie-Hellman'ı anlamak önemli, çünkü buradaki kavramlarla
anahtar değişimi gereken hemen her yerde karşılaşıyoruz.

## Nasıl? 

İşin özü şu: Herkese açık birkaç değişkeni kendi gizli değişkenlerimizle birleştirip aynı anahtarı üretiyoruz.

İlk bölümde konuyu genel hatlarıyla anlatacağım, sonra işin matematiğine geçeceğiz.

Bob ile Alice aynı anahtarı her biri kendi tarafında üretecek, böylece güvensiz bir ağda bile baş başa konuşabilecekler.

İşe değişkenlerimizi tanımlayarak başlayalım.

g - üreteç. Küçük bir asal sayı ve herkese açık.
<br>
n - büyük bir asal sayı, o da herkese açık
<br>
a - Alice'in gizli değişkeni (0 ile n arasında bir sayı).
<br>
b - Bob'un gizli değişkeni (0 ile n arasında bir sayı).
<br>
Gizli değişkenler asla paylaşılmaz.

Başlangıçta ağımız şöyle görünüyor.

```
Alice | Public | Bob
a     | g n    | b
```

Alice kendi gizli değişkenini g ile birleştirip yeni bir sayı üretiyor, buna "ag" diyelim.
<br>
Bob da aynı işlemi kendi gizli değişkeniyle yapıp "bg"yi elde ediyor.

ag - Alice'in paylaştığı değişken
<br>
bg - Bob'un paylaştığı değişken

```
Alice | Public | Bob
ag    |        | bg
```

Alice ürettiği sayıyı (ag) Bob'a gönderiyor.
Bob da aynı şekilde yeni ürettiği sayıyı (bg) Alice'e yolluyor.

```
Alice | Public | Bob
      | ag bg  |
```

Artık Alice'in elinde Bob'un paylaştığı değişken, Bob'un elinde de Alice'in paylaştığı değişken var.

```
Alice | Public | Bob
bg    |        | ag
```

Alice, kendi gizli değişkeni a'yı Bob'dan gelen bg ile birleştirip
bga'yı üretecek.
<br>
Bob da kendi gizli değişkeni b'yi Alice'ten gelen ag ile birleştirip
agb'yi üretecek.

İşin matematiği, agb ile bga'nın aynı çıkacağını garanti ediyor.

```
Alice | Public | Bob
bga   |        | agb
```

Bu kadar. Artık Bob'un da Alice'in de elinde aynı anahtar var.

## Matematik 

Aslında işin matematiği gayet basit.

g - küçük bir asal sayı.
<br>
n - Bunun işe yaraması için n'nin çok büyük olması gerekiyor. Brute force'u pratikte imkânsız kılacak kadar büyük.
<br>
a - 0 ile n arasında rastgele bir sayı.
<br>
b - 0 ile n arasında rastgele bir sayı.

Alice, g üzeri a mod n'yi hesaplayarak ag'yi elde ediyor.
<br>
Bob, g üzeri b mod n'yi hesaplayarak bg'yi elde ediyor.

```
ag = g**a mod n
bg = g**b mob n
```

Sonuçlar n'den küçük çıkacak ve ag ile bg'ye bakarak a'nın ya da b'nin ne olduğunu bulmak imkânsız.

ag ve bg'den yola çıkıp a ile b'yi bulmak, ayrık logaritma problemidir. Bu problem, günümüzün süper bilgisayarları için bile fazlasıyla zor.

Alice, bg'yi alıp kendi gizli sayısının kuvvetine yükseltiyor.
<br>
Bob da ag'yi alıp kendi gizli sayısının kuvvetine yükseltiyor.

```
agb = (g**b)**a mod n
bga = (g**a)**b mod n
```

Gördüğünüz gibi ikisi de aynı sayıya ulaştı.

```
shared_key = g**(ab) mod n
```

## Sonuç 

Modern uygulamalardaki şifrelemenin nasıl çalıştığını kavramak için Diffie-Hellman'ı anlamak önemli.

Diffie-Hellman'ın püf noktası şu: Açıkta dolaşan bilgileri nasıl birleştirirseniz birleştirin, gizli anahtarımıza ulaşamazsınız.

İşin aslı, Diffie-Hellman hiçbir zaman tek başına kullanılmaz; çünkü yalın hâliyle ortadaki adam (man-in-the-middle) saldırılarına karşı hiçbir koruma sunmaz.

Ayrık logaritma problemini çözmek hesaplama açısından çok maliyetli; ama NSA ya da dünyadaki diğer istihbarat teşkilatları gibi bu işe kendini adamış kurumların brute force denemeye fazlasıyla yetecek kaynakları olabilir.

Bu sorunlara, özellikle de anahtar değişimindeki ortadaki adam meselesine ileride ayrı bir yazıda değineceğim. Merak ediyorsanız şu anahtar kelimelerle kendi araştırmanızı yapabilirsiniz.

- RSA, PKI, SSL Sertifikaları, Dijital İmza

## Kaynaklar ve İleri Okuma 

[Secret Key Exchange (Diffie-Hellman) - Computerphile](https://www.youtube.com/watch?v=NmM9HA2MQGI)

[Diffie Hellman -the Mathematics bit- Computerphile](https://www.youtube.com/watch?v=Yjrfm_oRO0w)

[Key Exchange Problems - Computerphile](https://www.youtube.com/watch?v=vsXMMT2CqqE)

[Diffie–Hellman key exchange - Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
