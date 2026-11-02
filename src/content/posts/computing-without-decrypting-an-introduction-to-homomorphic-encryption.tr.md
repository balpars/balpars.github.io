---
title: "Şifre Çözmeden Hesaplamak: Homomorfik Şifrelemeye Giriş"
slug: computing-without-decrypting-an-introduction-to-homomorphic-encryption
author: balpars
published: 2026-08-12
draft: false
tags:
  - cryptography
description: "Sunucu ele geçirilse bile saldırgan aradığı her şeyi orada bulamasın diye nasıl bir sistem tasarlayabiliriz?"
toc: true
series: 'Cryptography Basics'
---

# Okuyamadığımız Veri Üzerinde Hesap Yapmak

## Çıkış Noktası

Veriyi şifrelemeyi aslında epey iyi beceriyoruz.

Diskte duran veriyi şifreleyebiliyoruz.

Ağda taşınan veriyi TLS ile koruyabiliyoruz.

Sorun, bu veriyi gerçekten **kullanmak** istediğimizde başlıyor.

Hassas müşteri bilgilerini işleyen bir sunucu düşünün.

Diskte dururken:

```text
Database
   ↓
Encrypted
```

Taşınırken:

```text
Client ─── TLS ─── Server
```

Ama er ya da geç uygulamanın bu bilgiyle bir şey yapması gerekiyor.

Belki kredi notu hesaplayacak.

Belki tıbbi ölçümleri analiz edecek.

Belki maaşlardan istatistik çıkaracak.

Geleneksel yöntemde bu şu demek:

```text
Encrypted Data
      ↓
   Decrypt
      ↓
  Plaintext
      ↓
  Calculate
      ↓
   Encrypt
```

Bu da ortaya ilginç bir güvenlik sorunu çıkarıyor.

Saldırganın illa AES'i kırması gerekmiyor.

TLS'i aşmasına da gerek yok.

Sunucunun kendisi ele geçirilmişse, uygulamanın veriyi çözmesini beklemek yeterli olabilir.

Şifreleme, bilgi saklanırken ve iletilirken üzerine düşeni yaptı.

Ama sonunda uygulamanın açık metne ihtiyacı oldu.

Peki bu gereksinimi düpedüz ortadan kaldırsak?

Ya sunucu, **neyin üzerinde hesap yaptığını hiç öğrenmeden** hesap yapabilseydi?

Şunun yerine:

```text
Encrypted Data
      ↓
   Decrypt
      ↓
  Plaintext
      ↓
 Compute
```

şöyle bir akış kurabilirdik:

```text
Encrypted Data
      ↓
 Compute
      ↓
Encrypted Result
```

Arada hiçbir noktada açık metin yok.

İşte **Homomorfik Şifreleme** fikrinin özü bu.

---

## Tuhaf Bir Fikir

Bir şirketin elinde şu maaş verileri olduğunu düşünün:

```text
50,000
72,000
91,000
```

Şirket buluttaki bir analitik servisinden yararlanmak istiyor.

Ama bulut sağlayıcısının çalışanların maaşlarından hiçbirini öğrenmesini istemiyor.

Normalde bu iki istek birbiriyle çelişir.

Sunucunun veriyle ilgili bir şey hesaplayabilmesi için verinin kendisine ihtiyacı vardır.

Homomorfik Şifreleme bu varsayımı değiştiriyor.

Şirket önce değerleri kendi tarafında şifreliyor:

```text
50000  ──encrypt──>  ciphertext_1
72000  ──encrypt──>  ciphertext_2
91000  ──encrypt──>  ciphertext_3
```

Buluta yalnızca şifreli metin ulaşıyor.

Bulut şu hesabı yapıyor:

```text
ciphertext_1
      +
ciphertext_2
      +
ciphertext_3
```

ve sonuçta yine şifreli bir metin elde ediyor.

Sonuç şirkete geri dönüyor.

Gizli anahtar yalnızca şirkette olduğu için cevabı da yalnızca şirket çözebiliyor.

Kavramsal düzeyde akış şöyle:

```text
CLIENT

[50000, 72000, 91000]
          |
          | Encrypt
          v

   Encrypted Salaries
          |
          |
          v

CLOUD SERVER

   Encrypted Salaries
          |
          | Compute
          v
    Encrypted Result
          |
          |
          v

CLIENT

    Encrypted Result
          |
          | Decrypt
          v

         71000
```

Bulut, tek bir maaşı bile öğrenmeden ortalama maaşı hesapladı.

Bu bile başlı başına ilginç.

Ama güvenlik açısından beni daha da çok ilgilendiren başka bir sonucu var.

## İhlal Anında Ne Olur?

Analitik sunucumuzun ele geçirildiğini varsayalım.

Geleneksel bir mimaride saldırganın eline şunlar geçebilir:

```text
Application memory
Database credentials
Temporary files
Application logs
Plaintext values currently being processed
```

Veritabanı şifreli olsa bile uygulama, çalışmak için açık metne ihtiyaç duyduğundan şifre çözme anahtarına genellikle bir yerden erişebilir.

Düzgün tasarlanmış homomorfik bir sistemde ise hesaplama sunucusunun **gizli anahtara hiç ihtiyacı yoktur**.

Şifreli metin alır.

Şifreli metin üzerinde hesap yapar.

Şifreli metin döndürür.

Gizli anahtar başka bir yerde kalır.

Bu yüzden hesaplama ortamı ele geçirildiğinde ortaya bambaşka bir tablo çıkabilir:

```text
Attacker compromises server
          |
          v

Encrypted input
Encrypted intermediate values
Encrypted output
Public/evaluation keys
```

şunun yerine:

```text
Attacker compromises server
          |
          v

Plaintext customer dataset
```

Bu, ihlalleri zararsız kılmaz.

Metadata yine de sızabilir.

Uygulama mantığında yine de zafiyet olabilir.

Gizli anahtarı tutan istemci de ele geçirilebilir.

Sonuçlar da kendi başına bilgi sızdırabilir.

Üstelik Homomorfik Şifreleme, kötü niyetli her sunucuya karşı bütünlüğü sihirli bir şekilde garanti etmez.

Ama özellikle tehlikeli bir varsayımı büyük ölçüde geçersiz kılabilir:

> Hesaplamayı yapan makinenin asıl veriye erişmesi illa gerekmez.

Buna bazen **kullanımdaki verinin** (data in use) korunması da deniyor.

---

## Okuyamadığın Bir Şeyle Nasıl Hesap Yaparsın?

Diyelim ki:

```text
Enc(x)
```

ifadesi `x` değerinin şifrelenmiş halini gösteriyor.

Homomorfik şifreleme şemalarında şifreli metin üzerinde yapılan belirli işlemler, açık metin üzerindeki işlemlere karşılık gelir.

Kavramsal olarak:

```text
Enc(10) + Enc(20)
```

işlemi, çözüldüğünde şunu veren bir şifreli metin üretir:

```text
30
```

Toplamayı yapan tarafın, asıl değerlerin `10` ve `20` olduğunu bilmesine hiç gerek yok.

Benzer şekilde:

```text
Enc(10) * 5
```

işlemi de çözüldüğünde şunu veren şifreli bir değer üretebilir:

```text
50
```

Gerçek implementasyon, bu gösterimin düşündürdüğünden elbette çok daha karmaşık.

Modern şemalar büyük ölçüde kafes tabanlı kriptografiye ve polinom aritmetiğine dayanıyor.

Ama işin bize lazım olan kısmını anlamak için önce matematiğini baştan türetmemiz gerekmiyor.

---

## Sadece Toplama ve Çarpma mı?

İlk bakışta bu kulağa şaşırtıcı derecede kısıtlı geliyor.

Yapabildiğimiz tek şey şunlarsa:

```text
+
*
```

işe yarar programları nasıl çalıştıracağız?

Cevap şu: bu işlemler göründüklerinden çok daha güçlü.

Şuna bakalım:

```text
3x² + 2x + 5
```

Bunu yalnızca çarpma ve toplamayla hesaplayabiliriz.

Ağırlıklı skor:

```text
0.5x₁ + 0.2x₂ + 0.3x₃
```

da sadece çarpma ve toplamadan ibaret.

İç çarpım:

```text
x₁w₁ + x₂w₂ + x₃w₃
```

yine çarpma ve toplamadan oluşur.

Bu yapı taşlarıyla örneğin şunları kurabiliriz:

```text
Averages
Weighted scores
Variance
Dot products
Matrix operations
Linear regression
Parts of machine-learning models
```

CKKS implementasyonları şifreli metin rotasyonu gibi işlemler de yapabiliyor; değerler şifreli vektörlere paketlendiğinde bu çok işe yarıyor. OpenFHE'nin kendi örneklerinde de paketlenmiş değerler üzerinde homomorfik toplama, çarpma ve rotasyon işlemlerini görebilirsiniz.

Ama programda şunun gibi işlemler varsa işler karışıyor:

```python
if x > 50:
    ...
```

ya da:

```python
max(x, 0)
```

CKKS gibi şemalarda karşılaştırma ve dallanma, doğal aritmetik işlemler değil.

ReLU'yu ele alalım:

```text
ReLU(x) = max(0, x)
```

HE kullanan bir uygulama, `max()` fonksiyonunu doğrudan hesaplamak yerine onu bir polinomla yaklaşık olarak ifade edebilir:

```text
ReLU(x) ≈ a + bx + cx² + dx³ + ...
```

Böylece problem birden yine şuna indirgenir:

```text
+
*
```

Microsoft SEAL'i geliştirenler de CKKS'te polinom olmayan fonksiyonları hesaplamanın yollarından birinin polinom yaklaşımı olduğunu söylüyor.

Bu önemli bir kısıtlama.

Homomorfik Şifreleme kullanmak, elimizdeki herhangi bir Python yazılımını alıp şunu:

```python
x = 10
```

şununla değiştirip:

```python
x = encrypted(10)
```

her şeyin çalışmasını bekleyebiliriz demek değil.

Algoritmaları çoğu zaman, şifreli veride verimli çalışan işlemlere göre yeniden tasarlamak gerekiyor.

---

# Python'da Deneyelim

Bunu biraz somutlaştıralım.

Microsoft SEAL'in sunduğu homomorfik şifreleme kavramları üzerine kurulmuş bir Python kütüphanesi olan **TenSEAL**'i kullanacağız.

Kurulum için:

```bash
pip install tenseal
```

Şemamız CKKS olacak.

CKKS özellikle reel sayılarla yaklaşık aritmetik yapmak için kullanışlı.

Önce:

```python
import tenseal as ts
```

Şimdi **istemci** tarafında bir context oluşturuyoruz.

```python
client_context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)

client_context.global_scale = 2**40
client_context.generate_galois_keys()
```

Bu parametrelerin tam olarak ne anlama geldiği başlı başına bir yazıyı hak ediyor.

Şimdilik şunu bilmek yeterli: bu context, CKKS işlemlerimiz için gereken kriptografik materyali barındırıyor.

Gizli veri setimiz:

```python
salaries = [
    50000.0,
    72000.0,
    91000.0
]
```

Şifreleyelim:

```python
encrypted_salaries = ts.ckks_vector(
    client_context,
    salaries
)
```

Artık elimizde, bulutun asıl değerleri bilmeden işleyebileceği bir şey var.

---

## Gizli Anahtarı Dışarıda Bırakmak

Demoyu ilginç kılan kısım burası.

İstemci context'imizin tamamını buluta göndermek **istemiyoruz**.

Bu, kurduğumuz mimarinin bütün amacını boşa çıkarırdı.

Bunun yerine context'in gizli anahtar içermeyen bir kopyasını serileştiriyoruz:

```python
server_context_bytes = client_context.serialize(
    save_public_key=True,
    save_secret_key=False,
    save_galois_keys=True,
    save_relin_keys=True
)
```

Şifreli metni de serileştiriyoruz:

```python
encrypted_salaries_bytes = encrypted_salaries.serialize()
```

Hesaplama sunucusuna gönderebileceğimiz şey bu byte'lardan ibaret.

Sunucu kendi context'ini yeniden oluşturuyor:

```python
server_context = ts.context_from(server_context_bytes)
```

Şimdi bir şeyi kontrol edelim:

```python
print(server_context.has_secret_key())
```

Çıktı şu olmalı:

```text
False
```

Gizli anahtarımız sunucuda yok.

TenSEAL'in kendi serileştirme testleri de, açık anahtar ve evaluation anahtarlarıyla birlikte ama gizli anahtar olmadan serileştirilen context'leri açıkça test ediyor.

Şimdi sunucu şifreli vektörü yeniden oluşturuyor:

```python
server_salaries = ts.ckks_vector_from(
    server_context,
    encrypted_salaries_bytes
)
```

TenSEAL'deki `ckks_vector_from()` fonksiyonu tam da serileştirilmiş bir CKKS vektörünü yükleyip bir context'e bağlamak için var.

---

# Sunucuda Hesaplama

Diyelim ki her çalışana %10 zam yapıp üstüne 1000'lik sabit bir prim vermek istiyoruz.

Açık metin üzerinde bunu şöyle yazardık:

```python
new_salary = salary * 1.10 + 1000
```

Sunucu aynı hesabı şifreli vektörümüz üzerinde birebir yapabilir:

```python
encrypted_new_salaries = (
    server_salaries * 1.10
) + 1000
```

Neyin eksik olduğuna dikkat edin.

Hiçbir yerde şu yok:

```python
decrypt()
```

Sunucunun buna hiç ihtiyacı yok.

Sadece şunu geri gönderiyor:

```python
result_bytes = encrypted_new_salaries.serialize()
```

---

## Sunucu Şifreyi Çözebilir mi?

Deneyelim.

```python
server_salaries.decrypt()
```

Sunucu context'inde gizli anahtar olmadığından bu çağrının hata vermesi gerekiyor.

Zaten istediğimiz de tam olarak buydu.

Hesaplama düğümümüz şifreli metin üzerinde işlem yapmayı biliyor.

Ama açık metni geri elde etmeyi bilmiyor.

---

# İstemci Tarafına Dönüş

Sunucu bize şunu gönderiyor:

```text
result_bytes
```

Gizli anahtarı içeren asıl context hâlâ istemcide.

Sonucu bu context'le yeniden oluşturuyoruz:

```python
encrypted_result = ts.ckks_vector_from(
    client_context,
    result_bytes
)
```

Artık şifreyi çözebiliriz:

```python
result = encrypted_result.decrypt()

print(result)
```

Çıktı yaklaşık şöyle:

```text
[56000, 80200, 101100]
```

Çok küçük kayan nokta farkları görebilirsiniz.

CKKS kesin değil yaklaşık aritmetik yaptığından bu zaten beklenen bir durum.

Baştan sona akış şöyleydi:

```text
CLIENT
------------------------------------------------

salary = [50000, 72000, 91000]

          |
          | encrypt
          v

ciphertext

          |
          | send
          v


SERVER
------------------------------------------------

secret key: NO

ciphertext

          |
          | * 1.10
          | + 1000
          v

new ciphertext

          |
          | send
          v


CLIENT
------------------------------------------------

new ciphertext

          |
          | decrypt
          v

[56000, 80200, 101100]
```

Sunucu çalışanların maaşlarını işledi ama hiçbirini öğrenmedi.

---

# İhlal Simülasyonu

Şimdi bir saldırganın buluttaki hesaplama düğümümüzü ele geçirdiğini düşünün.

Saldırganın eline şunlar geçiyor:

```python
server_context
server_salaries
encrypted_new_salaries
```

Hatta şunu çalıştırabilir:

```python
print(server_context.has_secret_key())
```

ve şu cevabı alır:

```text
False
```

Şifreli maaş veri setini kopyalayabilir.

Çalışan süreci inceleyebilir.

Sunucu context'ini çalabilir.

Ama gizli anahtar orada yok, bu kadar basit.

Bu tablo, şu senaryodan çok farklı:

```text
Server compromised
        ↓
Database dumped
        ↓
Customer records recovered
```

Son derece değerli bir varlığı, yani veriyi çözebilme yetisini, hesaplama ortamının dışına çıkardık.

Tabii bu durumda anahtar yönetimi kritik hale geliyor.

İstemcimiz ya da anahtarı tutan servis ele geçirilirse güvenlik sınırı çöker.

Kriptografi, güven ihtiyacını nadiren tamamen ortadan kaldırır.

Daha çok, **güveni daha küçük ve savunması daha kolay bir yere taşımamızı sağlar**.

Bence Homomorfik Şifrelemeye bu açıdan bakmak çok daha faydalı.

---

# Peki Bunu Neden Her Yerde Kullanmıyoruz?

Çünkü bunun bir bedeli var.

Sıradan bir CPU şunu görür:

```python
42.0 * 1.10
```

ve küçücük bir donanım işlemi yapar.

Homomorfik Şifreleme ise bambaşka bir şey görür.

Tek bir şifreli metin, binlerce katsayılı büyük polinom yapıları içerebilir.

İşlemler de bu yapılar üzerinde modüler aritmetikle yapılır.

Yani şu işlem:

```python
encrypted_salary * 1.10
```

şunun kadar ucuz olmanın yanından bile geçmez:

```python
salary * 1.10
```

Maliyet birkaç farklı yerde karşımıza çıkıyor.

## Hesaplama

Şifreli aritmetik, açık metindeki karşılığından birkaç mertebe daha pahalı olabilir.

Çarpma burada özellikle önemli, çünkü art arda yapılan çarpmalar gereken hesaplama derinliğini artırır.

Microsoft SEAL'in dokümantasyonu bile, işlevsel açıdan aynı olan iki HE implementasyonu arasında, hesaplamanın nasıl kurgulandığına bağlı olarak **birkaç mertebelik** performans farkı olabileceği konusunda uyarıyor.

Dolayısıyla şu tarz, her yerde geçerli ve işe yarar bir rakam vermek mümkün değil:

```text
Homomorphic Encryption = 100x slower
```

Bir iş yükü için kabul edilebilir olan, bir başkasında tamamen pratik dışı kalabilir.

---

## Bellek

Şu sayı:

```text
42.0
```

normalde double tipinde sekiz byte'la tutulabilir.

Aynı sayının homomorfik şifreli metni ise kat kat büyük olabilir.

Tek bir küçücük sayı yerine büyük polinom katsayıları içeren kriptografik nesneler saklıyoruz.

Bu durum önbelleği, RAM kullanımını ve serileştirmeyi de etkiliyor.

---

## Ağ

Şifreli metindeki bu büyüme, makineler arasında veri taşırken de kendini gösteriyor.

Şunu göndermek:

```text
1 MB plaintext
```

illa ki şunu göndermek anlamına gelmiyor:

```text
1 MB ciphertext
```

Şifreli nesneler çok daha büyük olabilir.

Bu yüzden dağıtık uygulamalarda ağ maliyetini de performans hesabına katmak gerekebilir.

---

# Çarpmanın Bir Sorunu Daha Var

Art arda çarpmaların önemli olmasının bir nedeni daha var.

Homomorfik şifreli metinler gürültü içerir.

Çok kabaca anlatmak gerekirse, başlangıçta şöyle görünen bir şifreli metin düşünün:

```text
Useful signal: ███████████████████
Noise:         █
```

Biraz daha hesaplama yaptıktan sonra:

```text
Useful signal: ███████████████████
Noise:         █████
```

Yeterince karmaşık bir hesaplamadan sonra ise:

```text
Useful signal: ███████████████████
Noise:         ███████████████
```

Sonunda, sonucu yeterli doğrulukta geri elde edememe riski doğar.

CKKS'te bunlara ek olarak, şifreli metinlerin çarpmalar boyunca nasıl değişeceğini belirleyen seviye (level) ve yeniden ölçekleme (rescaling) kavramları da var.

Bir programın **çarpımsal derinliği** de bu yüzden bu kadar önemli.

Örneğin:

```text
x + x + x + x + x
```

ifadesiyle şunu art arda hesaplamak arasında büyük fark var:

```text
((((x * x) * x) * x) * x)
```

İkinci ifade çok daha derin bir çarpma zinciri oluşturur.

Microsoft SEAL'in CKKS örneklerinin ölçek ve modulus seviyesi yönetimine bu kadar yer ayırmasının sebebi de tam olarak bu.

---

# Bootstrapping

Ve sonunda Tam Homomorfik Şifrelemenin en bilinen kavramlarından birine geliyoruz:

**bootstrapping**.

Çok kabaca söylersek bootstrapping, şifreli metni tazeleyip üzerinde hesaplamaya devam edebilmemizi sağlar.

Bunu, şöyle bir şifreli metni:

```text
Ciphertext
Noise: █████████████
```

yeniden şuna yakın bir hale getirmek gibi düşünebilirsiniz:

```text
Fresh Ciphertext
Noise: ██
```

Üstelik bunu, içindeki açık metni ifşa etmeden yapar.

Tam Homomorfik Şifrelemeyi mümkün kılan fikirlerden biri de bu.

Aynı zamanda pahalı bir işlem.

Bu yüzden modern FHE kütüphaneleri bootstrapping'i optimize etmek için epey uğraşıyor; OpenFHE'de de CKKS bootstrapping için ayrı fonksiyonlar ve örnekler var.

Bunun arkasındaki matematiği başka bir yazıya bırakalım.

---

# FHE Sihirli Bir İhlal Kalkanı Değil

Bitirmeden önce önemli bir uyarı.

Şöyle düşünmek cazip gelebilir:

> Her şey işlenirken bile şifreli kalıyorsa, sunucunun ele geçirilmesi artık önemli değil.

Bu yanlış bir düşünce.

Homomorfik Şifreleme belirli bir güvenlik sınırını korur.

Saldırgan yine de şunları yapabilir:

```text
Modify computations
Steal metadata
Observe access patterns
Exploit the surrounding application
Compromise the key holder
Manipulate input or output
Attack another component that receives plaintext
```

Tehdit modelinin tam olarak ne olduğu da önemli.

Örneğin OpenFHE, homomorfik şemalarının güvenlik varsayımlarını açıkça belgeliyor ve ek korumalar uygulanmadıkça standart şemalarının temelde dürüst ama meraklı (honest-but-curious/semi-honest) modele göre tasarlandığını belirtiyor.

Yani ilginç olan iddia şu değil:

> Homomorfik Şifreleme ihlalleri zararsız kılar.

Asıl iddia şu:

> Homomorfik Şifreleme, asıl veriyi okumak için gereken sırrı bir hesaplama sistemine vermeden, o sistemin işe yarar bir iş yapmasını sağlayabilir.

Bu da saldırganın o sistemi ele geçirdiğinde eline geçebilecekleri kökten değiştirir.

---

# Sonuç

Homomorfik Şifrelemede beni en çok ilgilendiren şey, şu işlemin:

```text
Enc(5) + Enc(10)
```

sonucunun şu değerin şifreli hali olabilmesi değil:

```text
15
```

Bu hoş bir kriptografik numara.

Asıl önemli fikir mimariyle ilgili.

Normalde bir sunucuya hassas bilgiyi işleme yetkisi verdiğinizde, o bilgiyi de ona emanet etmiş olursunuz.

Homomorfik Şifreleme ile bu iki yetkiyi birbirinden ayırmaya başlayabiliyoruz:

```text
Permission to compute

does not necessarily imply

Permission to read
```

Bu, güçlü bir güvenlik yapı taşı.

Karşılığında hesaplama, bellek, bant genişliği ve karmaşıklık açısından ağır bir bedel ödüyoruz.

Ama yeterince hassas bilgi işleyen sistemlerde bu takas giderek ilginçleşiyor.

Özellikle de soru şundan:

> Sunucunun ele geçirilmesini nasıl önleriz?

şuna dönüştüğünde:

> Sunucu ele geçirilse bile saldırgan aradığı her şeyi orada bulamasın diye nasıl bir sistem tasarlayabiliriz?

Homomorfik Şifreleme tam da burada ilginçleşiyor.


## Kaynaklar

Bu yazıdaki kavramları daha derinlemesine incelemek isteyenler için faydalı kaynaklar:

1. **Microsoft SEAL**  
    Microsoft Research'ün açık kaynak homomorfik şifreleme kütüphanesi; pratik CKKS ve BFV implementasyonlarının arkasındaki başlıca kütüphanelerden biri.  
    [https://github.com/microsoft/SEAL](https://github.com/microsoft/SEAL)
2. **Microsoft SEAL — CKKS Temelleri Örneği**  
    Kodlama (encoding), ölçekler, modulus seviyeleri, çarpma, yeniden ölçekleme ve şifreli metin yönetimi gibi konularla CKKS'e uygulamalı bir giriş.  
    [https://github.com/microsoft/SEAL/blob/main/native/examples/5_ckks_basics.cpp](https://github.com/microsoft/SEAL/blob/main/native/examples/5_ckks_basics.cpp)
3. **TenSEAL**  
    Microsoft SEAL üzerine kurulu, Python'dan rahatça kullanılabilen bir homomorfik şifreleme kütüphanesi. Şifreli vektörler ve tensörler sunuyor; özellikle CKKS'le denemeler yapmak için çok pratik.  
    [https://github.com/OpenMined/TenSEAL](https://github.com/OpenMined/TenSEAL)
4. **TenSEAL: A Library for Encrypted Tensor Operations Using Homomorphic Encryption**  
    Ayoub Benaissa, Bilal Retiat, Bogdan Cebere, Alaa Eddine Belfedhal.  
    Makale TenSEAL'i tanıtıyor ve homomorfik şifrelemeyle gizliliği koruyan makine öğrenmesi iş yüklerini gösteriyor.  
    [https://arxiv.org/abs/2104.03152](https://arxiv.org/abs/2104.03152)
5. **OpenFHE Dokümantasyonu**  
    OpenFHE de öne çıkan açık kaynak FHE kütüphanelerinden biri. Dokümantasyonunda homomorfik aritmetik, paketlenmiş şifreli metinler, rotasyonlar ve çeşitli modern şemalarla ilgili örnekler var.  
    [https://openfhe-development.readthedocs.io/](https://openfhe-development.readthedocs.io/)
6. **OpenFHE CKKS Bootstrapping Örneği**  
    CKKS bootstrapping'i kod düzeyinde gösteren bir örnek. Bootstrapping, daha derin homomorfik hesaplamaları mümkün kılan temel tekniklerden biri.  
    [https://openfhe-development.readthedocs.io/en/latest/api/program_listing_file_pke_extras_ckks-bootstrap.cpp.html](https://openfhe-development.readthedocs.io/en/latest/api/program_listing_file_pke_extras_ckks-bootstrap.cpp.html)
7. **CKKS Explained — OpenMined**  
    CKKS şemasını kodlama katmanından başlayıp yukarı doğru anlatan faydalı bir yazı dizisi; yaklaşık homomorfik aritmetiğin ardındaki matematiksel sezgiyi de veriyor.  
    [https://openmined.org/blog/ckks-explained-part-1-simple-encoding-and-decoding/](https://openmined.org/blog/ckks-explained-part-1-simple-encoding-and-decoding/)
8. **CKKS.org**  
    CKKS homomorfik şifreleme şeması hakkında bir kaynak derlemesi; şemanın reel ve karmaşık sayılarla yaklaşık hesaplamada kullanımını da kapsıyor.  
    [https://ckks.org/](https://ckks.org/)
9. **CryptoNets: Applying Neural Networks to Encrypted Data**  
    Şifreli veri üzerinde doğrudan sinir ağı çıkarımı yapılabileceğini gösteren, erken dönemin etkili çalışmalarından biri.  
    [https://arxiv.org/abs/1412.6181](https://arxiv.org/abs/1412.6181)

