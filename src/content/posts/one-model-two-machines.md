---
title: "One Model, Two Machines: Running an LLM That Fits on Neither"
author: balpars
published: 2026-11-01
draft: true
tags:
  - local_llm
  - distributed_inference
description: "How I ran an LLM that fits on neither of my machines by splitting it across both, and got it to a usable 39 tokens/s."
toc: true
series: 'Local LLMs'
---

# One Model, Two Machines: Running an LLM That Fits on Neither

I have a 16 GB Mac mini and a Windows PC with a 12 GB graphics card. Neither can run a 27B model on its own.

What happens if I ask them to run it together?

## Motivation

It started with an Instagram reel (doomscroll FTW!). Someone on r/LocalLLaMA had connected an iPhone to a MacBook over USB-C and used the phone as a second GPU. The Mac handled the first part of the model, while the phone handled the rest. The project is called [Backburner](https://github.com/StayLameBro/backburner).

My first thought was that it couldn't be fast. A 10 Gb/s cable is roughly a hundred times slower than the memory inside a computer. Surely that would become a massive bottleneck?

It turns out, not necessarily. Once I understood why, I wanted to try the same idea with the hardware already sitting on my desk.

The result: a 35B model that fits on neither machine ran at 28 tokens per second. Over Wi-Fi. With a single Ethernet cable, it hit 39.

## How Does This Even Work?

A language model is a stack of layers. The 27B model I tested has 64 of them, and every token passes through them in order.

Each layer takes a list of numbers, multiplies it by its weights, and passes a new list of the same size to the next layer. That list is called the *hidden state*.

Here is the useful part: the layers don't all have to live on the same machine. I can put the first 43 layers on one device and the rest on another.

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

The weights are loaded once and stay on their respective machines. The only thing crossing the network is the hidden state. This setup is called *pipeline parallelism*.

So how much data are we actually sending?

```plain
hidden size        ~5,000 numbers
precision          16 bit = 2 bytes
per token          ~5,000 x 2 = ~10 KB
10 Gb/s link       ~1.25 GB/s
capacity           ~1.25 GB / 10 KB = ~100,000 tokens/s
```

The model processes at most a few hundred tokens per second. The cable is barely doing any work.

My concern would have made sense with a different setup. If one machine only stored the weights while the other did all the computation, gigabytes would have to cross the network for every token. Pipeline parallelism does the opposite: it moves the computation to the data, not the data to the computation.

The weights stay put. Only about 10 KB per token travels.

There is a catch, though. During generation, tokens come out one at a time. Each token's hidden state crosses the network twice, to the PC and back, so latency matters more than bandwidth.

And the two machines still work one after the other, not simultaneously. Pipeline parallelism gives you more memory to work with, not more speed.

## The Two Machines

Nothing exotic here. Just two machines I already had:

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

Together, that's roughly 23 GB of fast memory. Separately, neither machine has more than about 12 GB available for the model.

I picked two models for the test:

- **Model A, dense:** Qwen3.8-27B, Unsloth UD-Q4\_K\_M, 15.3 GiB, 64 layers.
- **Model B, MoE:** Qwen3.6-35B-A3B, bartowski IQ4\_XS, 18.3 GiB, 40 layers. It has 35B parameters in total, but only about 3B are used for each token.

Before splitting Model A, I tried loading it on the Mac by itself. llama.cpp didn't refuse to load it; it just warned and kept going. Within 16 seconds, the Mac was already 1.7 GB into swap.

That was enough to confirm the problem.

## Setting It Up

I used llama.cpp's RPC backend. It lets one machine expose its GPU over the network, while another machine treats that GPU as if it were connected locally.

Ollama is built on llama.cpp too, but it doesn't expose RPC. So I went with plain llama.cpp.

The roles were:

```plain
Mac mini  -> host    llama-server / llama-bench (Metal), owns the model files
PC        -> worker  ggml-rpc-server (Vulkan, B580), no model files needed
```

One important detail: both machines need to run the exact same llama.cpp build. The RPC protocol can change between versions. I used build `b11960` on both sides: `macos-arm64` on the Mac and `win-vulkan-x64` on the PC.

### Why Vulkan?

I used Vulkan instead of Intel's SYCL backend because, on the B580, Vulkan is consistently faster in llama.cpp. A quick check with a small 4B model gave me about 108 tokens/s on the card alone.

### On the PC

Start the RPC server:

```
ggml-rpc-server.exe -d Vulkan0 -H 0.0.0.0 -p 50052 -c
```

The flags:

```plain
-d Vulkan0     use only the B580
-H 0.0.0.0     listen on the network (default is 127.0.0.1, local only)
-p 50052       port
-c             cache received weights on disk
```

The server has no authentication, so I opened the port in Windows Firewall for exactly one IP address: the Mac's.

```
New-NetFirewallRule -DisplayName 'llama.cpp RPC 50052 (Mac mini only)' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 50052 `
  -RemoteAddress <MAC_IP> -Profile Private `
  -Program 'C:\llm\llama.cpp\ggml-rpc-server.exe'
```

### On the Mac

Run a benchmark with the PC added as an extra device:

```bash
llama-bench -m Qwen3.8-27B-UD-Q4_K_M.gguf -ngl 99 \
  --rpc <PC_IP>:50052 -p 512 -n 128 -ts 65/35
```

The `-ts 65/35` setting sends 65% of the model to the PC. The B580 reads memory almost four times faster than the M4, so it gets the larger share.

To chat with the model, start `llama-server` with the same flags and open `http://127.0.0.1:8080` in a browser. It also exposes an OpenAI-compatible API, so other tools can use it.

## Results

Both models loaded and ran. More importantly, the Mac didn't touch swap once.

I was aiming for 15–20 tokens per second from a model that couldn't fit on either machine alone. The MoE model cleared that target over Wi-Fi.

```text
                      Model A (27B dense)   Model B (35B-A3B MoE)
Split (PC / Mac)      65 / 35               50 / 50
Prompt, pp512         92.7 tok/s            319.6 tok/s
Generation, tg128     8.5 tok/s             28.3 tok/s
First load            11 min 46 s           9 min 41 s
Swap on the Mac       +0 MB                 +0 MB
```

I also checked where the weights actually ended up. The `model buffer size` lines in the llama.cpp logs show the split:

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

Remember the solo attempt? The Mac had tried to put 14.3 GB on its GPU. With the model split, its share dropped to 5.8 GB.

## Why Is the Dense Model So Much Slower?

A dense model reads all of its weights for every token. The Mac's roughly 6 GB share alone takes about 50 ms per token at 120 GB/s. Add the B580's share and the network round trips, and you end up at 8.5 tokens/s.

The MoE model only touches a small slice of its weights for each token. Memory reads become much less of a problem, and most of what's left is network latency.

Same machines, same network. The MoE model ran 3.3x faster.

## Three Quick Gotchas

**The device order flips.** `--list-devices` shows the Mac first, but the model loads onto the PC first. So `-ts 65/35` means 65% goes to the PC.

**Windows adds its own firewall rules.** One click on "Allow" in a popup opened the port to everyone. I deleted those rules and kept only the one I created.

**The worker can't read local model files.** The first load sent about 9.5 GB over Wi-Fi and took roughly 10 minutes. With the `-c` flag, later loads come from the PC's disk cache.

## So What's Holding It Back?

Two things: the network and pipeline parallelism itself.

### The Network

Since generation speed is mostly about latency, the obvious next step was to try a cable.

So I connected the Mac mini and the PC directly with a single Ethernet cable.

Before rerunning the benchmarks, I wrote down what I expected. Here's how that went:

```plain
                      Wi-Fi      Ethernet   My guess
Model A, prompt       92.7       141.6      ~102-107
Model A, generation   8.5        9.4        ~11-12
Model B, prompt       319.6      571.7      ~352-368
Model B, generation   28.3       39.4       ~40-50
(all in tok/s)

Connection latency    8.2 ms     1.2 ms
```

I got the MoE model right and almost everything else wrong.

**Generation.** Latency dropped about 7x. Model B, which does very little computation per token, gained 39%. Model A gained only 11%: its time per token went from 118 ms to 106 ms. So the network was only costing the dense model about 12 ms per token. The rest is memory reads, mostly the Mac's slower share. For the dense model, the bottleneck is the Mac, not the cable.

**Prompt processing.** I expected almost no change here. Instead it jumped 53% and 79%. A 512-token batch sends a few megabytes of hidden states, not a few kilobytes, and my Wi-Fi was only moving 12–21 MB/s. Those transfers were eating a big chunk of every batch.

Loading also got much faster, about 70 seconds instead of \~10 minutes. But that's mostly the `-c` cache on the PC, not the cable, so I'm not counting it.

### Real Speedups Need Tensor Parallelism

Pipeline parallelism gives you more memory, not more speed. For actual speedups, I'd need tensor parallelism, which splits every layer across machines and requires microsecond-level latency.

On Macs, that means RDMA over Thunderbolt 5. A base M4 Mac mini—or a Mac and PC combination like mine—can't do that.

## Conclusion

Combining two ordinary machines to run a model neither can handle alone is very doable today. I didn't buy anything. I installed llama.cpp, added one firewall rule, and plugged in a cable.

The part I didn't expect was how much the choice of model would matter.

**Picking the right model matters more than the network.**

Over Ethernet, the MoE model ran at 39.4 tokens/s, 4.2x faster than the dense model's 9.4 tokens/s. The cable gave the MoE model +39%, but the dense model only +11%. If you're trying this yourself, I'd start with an MoE model and give the dense layers to whichever device has the fastest memory.

## References

- [Backburner](https://github.com/StayLameBro/backburner) — Turns an iPhone into a co-processor for a Mac over USB-C. This is what started it all.
- [llama.cpp](https://github.com/ggml-org/llama.cpp) — The inference engine, including the RPC backend used here.
- [llama.cpp distributed benchmarks](https://github.com/kjaiswal/llama-cpp-distributed-benchmarks) — Benchmarks for llama.cpp RPC across Metal and CUDA over 10GbE.
- [Intel Arc B580 for Local LLMs](https://insiderllm.com/guides/intel-arc-b580-local-llm/) — Why Vulkan beats SYCL on the B580.
- [exo and RDMA over Thunderbolt 5](https://noqta.tn/en/blog/exo-distributed-ai-cluster-apple-silicon-local-llm-2026) — How Mac clusters use tensor parallelism.
