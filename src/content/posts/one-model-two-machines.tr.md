---
title: "Tek Model, İki Makine: Tek Başına İkisine de Sığmayan Bir LLM'i Çalıştırmak"
slug: one-model-two-machines
author: balpars
published: 2026-11-01
draft: false
tags:
  - local_llm
  - distributed_inference
description: "İki makineme de tek başına sığmayan bir LLM'i ikisine bölerek çalıştırdım ve 39 tokens/s ile kullanılabilir bir hıza çıkardım."
toc: true
series: 'Local LLMs'
---

Elimde 16 GB'lık bir Mac mini ve 12 GB'lık ekran kartı olan bir Windows PC var. 27B'lik bir modeli ikisi de tek başına çalıştıramıyor.

Peki bu işi birlikte yapsalar ne olur?

## Motivasyon

Her şey bir Instagram reel'iyle başladı (çok yaşa doomscroll!). r/LocalLLaMA'da biri iPhone'u USB-C ile MacBook'a bağlayıp telefonu ikinci GPU olarak kullanmış. Modelin ilk kısmını Mac, kalanını telefon işliyordu. Projenin adı [Backburner](https://github.com/StayLameBro/backburner).

İlk aklıma gelen, bunun hızlı olamayacağıydı. 10 Gb/s'lik bir kablo, bilgisayarın içindeki bellekten kabaca yüz kat yavaş. Bunun devasa bir darboğaz yaratacağı belliydi, değil mi?

Meğer öyle olmak zorunda değilmiş. Nedenini anlayınca aynı fikri zaten masamda duran donanımla denemek istedim.

Sonuç: İki makineye de sığmayan 35B'lik bir model saniyede 28 token hızında çalıştı. Hem de Wi-Fi üzerinden. Tek bir Ethernet kablosuyla bu sayı 39'a çıktı.

## Bu Nasıl Çalışıyor ki?

Dil modeli dediğimiz şey, üst üste dizilmiş layer'lardan oluşuyor. Test ettiğim 27B'lik modelde bunlardan 64 tane var ve her token hepsinden sırayla geçiyor.

Her layer bir sayı listesi alıyor, bunu kendi ağırlıklarıyla çarpıyor ve aynı boyutta yeni bir listeyi sonraki layer'a veriyor. Bu listeye *hidden state* deniyor.

İşin güzel yanı şu: Layer'ların hepsinin aynı makinede durması gerekmiyor. İlk 43 layer'ı bir cihaza, kalanını başka bir cihaza koyabilirim.

```plain
Mac mini (host)                         PC (worker)
+--------------------------+           +--------------------------+
| 1. token -> embedding    |           |                          |
|                          | --10 KB-> | 2. layers 0-42 (B580)    |
| 3. layers 43-63 + output | <-10 KB-- |    8.7 GB of weights     |
|    5.8 GB of weights     |           |                          |
+--------------------------+           +--------------------------+
             weights never move after loading
```

Ağırlıklar bir kez yükleniyor ve her biri kendi makinesinde kalıyor. Ağ üzerinden giden tek şey hidden state. Bu düzene *pipeline parallelism* deniyor.

Peki aslında ne kadar veri gönderiyoruz?

```plain
hidden size        ~5,000 numbers
precision          16 bit = 2 bytes
per token          ~5,000 x 2 = ~10 KB
10 Gb/s link       ~1.25 GB/s
capacity           ~1.25 GB / 10 KB = ~100,000 tokens/s
```

Model saniyede en fazla birkaç yüz token işliyor. Kabloya neredeyse hiç iş düşmüyor.

Kurulum farklı olsaydı endişemde haklı çıkardım. Bir makine sadece ağırlıkları tutsa ve bütün hesaplamayı diğeri yapsaydı, her token için ağdan gigabaytlarca veri geçmesi gerekirdi. Pipeline parallelism bunun tam tersini yapıyor: Veriyi hesaplamanın yanına değil, hesaplamayı verinin yanına taşıyor.

Ağırlıklar yerinden kıpırdamıyor. Token başına yol alan veri sadece 10 KB civarında.

Yalnız bir pürüz var. Üretim sırasında token'lar tek tek çıkıyor ve her token'ın hidden state'i ağı iki kez geçiyor: PC'ye gidiyor, sonra geri dönüyor. Bu yüzden burada bant genişliğinden çok gecikme önemli.

Üstelik iki makine yine de aynı anda değil, sırayla çalışıyor. Pipeline parallelism size hız değil, bellek kazandırıyor.

## İki Makine

Ortada egzotik bir şey yok, zaten elimde olan iki makine:

**Mac mini**

```plain
chip        Apple M4
memory      16 GB unified, ~12 GB usable by the GPU
bandwidth   ~120 GB/s
```

**Windows PC**

```plain
cpu         Intel Core i5-11400F
gpu         Intel Arc B580, 12 GB VRAM
bandwidth   ~456 GB/s (B580)
ram         64 GB DDR4 (big, but painfully slow for LLMs)
```

İkisi bir araya gelince kabaca 23 GB hızlı bellek ediyor. Tek tek bakınca ise ikisinde de model için 12 GB civarından fazla yer yok.

Test için iki model seçtim:

- **Model A, dense:** Qwen3.8-27B, Unsloth UD-Q4\_K\_M, 15.3 GiB, 64 layer.
- **Model B, MoE:** Qwen3.6-35B-A3B, bartowski IQ4\_XS, 18.3 GiB, 40 layer. Toplam 35B parametresi var ama her token'da bunun sadece 3B kadarı kullanılıyor.

Model A'yı bölmeden önce tek başına Mac'e yüklemeyi denedim. llama.cpp yüklemeyi reddetmedi, bir uyarı verip devam etti. Daha 16 saniye geçmeden Mac 1.7 GB swap kullanmaya başlamıştı.

Sorunu teyit etmeye bu kadarı yetti.

## Kurulum

llama.cpp'nin RPC backend'ini kullandım. Bu backend sayesinde bir makine GPU'sunu ağ üzerinden açabiliyor, diğer makine de o GPU'yu kendisine takılıymış gibi kullanabiliyor.

Ollama da llama.cpp üzerine kurulu ama RPC'yi dışarı açmıyor. O yüzden düz llama.cpp ile devam ettim.

Rol dağılımı şöyleydi:

```plain
Mac mini  -> host    llama-server / llama-bench (Metal), owns the model files
PC        -> worker  ggml-rpc-server (Vulkan, B580), no model files needed
```

Önemli bir ayrıntı: İki makinede de birebir aynı llama.cpp build'i çalışmalı, çünkü RPC protokolü sürümden sürüme değişebiliyor. Ben iki tarafta da `b11960` build'ini kullandım: Mac'te `macos-arm64`, PC'de `win-vulkan-x64`.

### Neden Vulkan?

Intel'in SYCL backend'i yerine Vulkan'ı kullandım, çünkü llama.cpp'de B580 üzerinde Vulkan her seferinde daha hızlı çıkıyor. Küçük bir 4B modelle yaptığım kısa bir denemede kart tek başına yaklaşık 108 tokens/s verdi.

### PC'de

RPC sunucusunu başlatıyoruz:

```
ggml-rpc-server.exe -d Vulkan0 -H 0.0.0.0 -p 50052 -c
```

Flag'ler:

```plain
-d Vulkan0     use only the B580
-H 0.0.0.0     listen on the network (default is 127.0.0.1, local only)
-p 50052       port
-c             cache received weights on disk
```

Sunucuda kimlik doğrulama yok. Bu yüzden portu Windows Firewall'da yalnızca tek bir IP adresine, Mac'inkine açtım.

```
New-NetFirewallRule -DisplayName 'llama.cpp RPC 50052 (Mac mini only)' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 50052 `
  -RemoteAddress <MAC_IP> -Profile Private `
  -Program 'C:\llm\llama.cpp\ggml-rpc-server.exe'
```

### Mac'te

PC'yi ek cihaz olarak ekleyip bir benchmark çalıştırıyoruz:

```bash
llama-bench -m Qwen3.8-27B-UD-Q4_K_M.gguf -ngl 99 \
  --rpc <PC_IP>:50052 -p 512 -n 128 -ts 65/35
```

`-ts 65/35` ayarı modelin %65'ini PC'ye gönderiyor. B580 belleği M4'ten neredeyse dört kat hızlı okuduğu için büyük payı o alıyor.

Modelle sohbet etmek isterseniz `llama-server`'ı aynı flag'lerle başlatıp tarayıcıdan `http://127.0.0.1:8080` adresine girmeniz yeterli. OpenAI uyumlu bir API de sunduğu için başka araçlar da ona bağlanabiliyor.

## Sonuçlar

İki model de yüklenip çalıştı. Daha da önemlisi, Mac swap'a bir kez bile dokunmadı.

Hedefim, iki makineye de tek başına sığmayan bir modelden saniyede 15–20 token almaktı. MoE model bu hedefi Wi-Fi üzerinden aştı.

```text
                      Model A (27B dense)   Model B (35B-A3B MoE)
Split (PC / Mac)      65 / 35               50 / 50
Prompt, pp512         92.7 tok/s            319.6 tok/s
Generation, tg128     8.5 tok/s             28.3 tok/s
First load            11 min 46 s           9 min 41 s
Swap on the Mac       +0 MB                 +0 MB
```

Ağırlıkların gerçekte nereye yerleştiğine de baktım. llama.cpp loglarındaki `model buffer size` satırları dağılımı gösteriyor:

**Model A**

```plain
RPC0 (PC, B580)    8,904 MiB   layers 0-42
MTL0 (Mac, GPU)    5,771 MiB   layers 43-63 + output
CPU  (Mac)           682 MiB   token embeddings
```

**Model B**

```plain
RPC0 (PC, B580)    9,062 MiB   21 layers
MTL0 (Mac, GPU)    8,601 MiB   21 layers + output
CPU  (Mac)           258 MiB   token embeddings
```

Tek başına yükleme denememi hatırlıyor musunuz? O sırada Mac, GPU'suna 14.3 GB yerleştirmeye çalışmıştı. Model bölününce Mac'in payı 5.8 GB'a indi.

## Dense Model Neden Bu Kadar Yavaş?

Dense model her token'da ağırlıklarının tamamını okuyor. Sadece Mac'e düşen yaklaşık 6 GB'lık payı 120 GB/s ile okumak bile token başına 50 ms civarı sürüyor. Üstüne B580'in payını ve ağdaki gidiş-dönüşleri eklediğinizde 8.5 tokens/s'de kalıyorsunuz.

MoE model ise her token'da ağırlıklarının sadece küçük bir dilimine dokunuyor. Bellek okumaları çok daha az dert oluyor, geriye kalan sürenin büyük kısmı da ağ gecikmesinden geliyor.

Makineler aynı, ağ aynı. Yine de MoE model 3.3 kat daha hızlı çalıştı.

## Üç Küçük Tuzak

**Cihaz sırası ters.** `--list-devices` Mac'i başta gösteriyor ama model önce PC'ye yükleniyor. Yani `-ts 65/35` dediğinizde %65 PC'ye gidiyor.

**Windows kendi firewall kurallarını ekliyor.** Çıkan bir pencerede bir kez "Allow"a tıkladım ve port herkese açıldı. O kuralları silip sadece kendi oluşturduğum kuralı bıraktım.

**Worker yerel model dosyalarını okuyamıyor.** İlk yüklemede Wi-Fi üzerinden 9.5 GB civarı veri gitti ve bu yaklaşık 10 dakika sürdü. `-c` flag'i sayesinde sonraki yüklemeler PC'nin disk önbelleğinden geliyor.

## Peki Hızı Ne Sınırlıyor?

İki şey: ağ ve pipeline parallelism'in kendisi.

### Ağ

Token üretim hızı büyük ölçüde gecikmeye bağlı olduğuna göre, akla gelen ilk adım kabloyu denemekti.

Ben de Mac mini ile PC'yi tek bir Ethernet kablosuyla doğrudan birbirine bağladım.

Benchmark'ları yeniden çalıştırmadan önce tahminlerimi bir kenara yazdım. Bakalım ne oldu:

```plain
                      Wi-Fi      Ethernet   My guess
Model A, prompt       92.7       141.6      ~102-107
Model A, generation   8.5        9.4        ~11-12
Model B, prompt       319.6      571.7      ~352-368
Model B, generation   28.3       39.4       ~40-50
(all in tok/s)

Connection latency    8.2 ms     1.2 ms
```

MoE modelde tahminim tuttu, geri kalanların neredeyse hepsinde yanıldım.

**Üretim.** Gecikme yaklaşık 7 kat düştü. Token başına çok az hesaplama yapan Model B %39 hızlandı. Model A ise sadece %11 hızlandı: Token başına süresi 118 ms'den 106 ms'ye indi. Demek ki ağın dense modele maliyeti token başına yalnızca 12 ms civarındaymış. Kalan süre bellek okumalarından, özellikle de Mac'in daha yavaş payından geliyor. Dense modelde darboğaz kablo değil, Mac.

**Prompt işleme.** Burada neredeyse hiç fark beklemiyordum. Oysa hız %53 ve %79 sıçradı. 512 token'lık bir batch birkaç kilobayt değil, birkaç megabayt hidden state gönderiyor; benim Wi-Fi'm ise ancak 12–21 MB/s taşıyordu. Bu aktarımlar her batch'in süresinden büyük bir pay yiyordu.

Yükleme de çok hızlandı: \~10 dakika yerine yaklaşık 70 saniye. Ama bunu kablodan çok PC'deki `-c` önbelleğine borçluyuz, o yüzden hesaba katmıyorum.

### Gerçek Hızlanma İçin Tensor Parallelism Gerekiyor

Pipeline parallelism'in kazandırdığı şey hız değil, bellek. Gerçekten hızlanmak için tensor parallelism gerekiyor. O da her layer'ı makineler arasında bölüyor ve mikrosaniye mertebesinde gecikme istiyor.

Mac'lerde bu, Thunderbolt 5 üzerinden RDMA demek. Standart bir M4 Mac mini de, benimki gibi bir Mac ve PC ikilisi de bunu yapamıyor.

## Sonuç

İki sıradan makineyi birleştirip ikisinin de tek başına kaldıramadığı bir modeli çalıştırmak bugün gayet mümkün. Yeni hiçbir şey almadım. llama.cpp'yi kurdum, tek bir firewall kuralı ekledim ve bir kablo taktım.

Beklemediğim şey, model seçiminin ne kadar fark yaratacağıydı.

**Doğru modeli seçmek ağdan daha önemli.**

Ethernet üzerinden MoE model 39.4 tokens/s hızında çalıştı, yani dense modelin 9.4 tokens/s'sinin 4.2 katı. Kablo MoE modele +%39 kazandırdı, dense modele ise yalnızca +%11. Siz de denemek isterseniz ben olsam işe bir MoE modelle başlar, dense layer'ları da belleği en hızlı olan cihaza verirdim.

## Kaynaklar

- [Backburner](https://github.com/StayLameBro/backburner) — iPhone'u USB-C üzerinden Mac'e yardımcı işlemci yapıyor. Her şeyi başlatan proje bu.
- [llama.cpp](https://github.com/ggml-org/llama.cpp) — Inference motoru. Burada kullandığım RPC backend'i de onun parçası.
- [llama.cpp distributed benchmarks](https://github.com/kjaiswal/llama-cpp-distributed-benchmarks) — 10GbE üzerinden, Metal ve CUDA arasında llama.cpp RPC benchmark'ları.
- [Intel Arc B580 for Local LLMs](https://insiderllm.com/guides/intel-arc-b580-local-llm/) — B580'de Vulkan'ın SYCL backend'ini neden geride bıraktığı.
- [exo and RDMA over Thunderbolt 5](https://noqta.tn/en/blog/exo-distributed-ai-cluster-apple-silicon-local-llm-2026) — Mac cluster'larında tensor parallelism'in nasıl kullanıldığı.
