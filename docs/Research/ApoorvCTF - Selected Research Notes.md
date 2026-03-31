---
title: Selected Security Research Notes
slug: /Research/ApoorvCTF-Selected-Research-Notes
sidebar_position: 3
custom_edit_url: null
---

This page collects selected security research notes written in a cleaner research-log format. The focus is on the attack path, the vulnerable assumption, and the shortest reliable route to recovery.

## Reverse Engineering

### Requiem

Running the binary only prints decoy text while the real flag is decoded internally and then hidden. Static analysis shows a small encoded blob in `.rodata` at offset `0x484f4`. The program XORs each byte with `0x5a` before use, so extracting `0x2d` bytes from that offset and applying the same XOR recovers the flag directly.

```python
from pathlib import Path

data = Path("requiem").read_bytes()
enc = data[0x484f4:0x484f4 + 0x2d]
flag = bytes(b ^ 0x5a for b in enc)
print(flag.decode())
```

Recovered flag:

`apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}`

### Cosmic Rings

The archive contains the real target binary `havok` together with `libc.so.6` and the matching loader. Symbols and debug information are still present, which makes reversing straightforward.

The first bug is in `calibrate_rings()`. An integer is read into a signed 32-bit variable and then truncated into a signed 16-bit index before indexing a local ring-value array. Negative full integers are rejected, but `65534` and `65535` become `-2` and `-1` after truncation, creating two out-of-bounds reads:

- `65534` leaks `puts@GOT`
- `65535` leaks the PIE address of `main`

That gives libc and PIE bases. The second bug is in `inject_plasma()`, which reads `0x30` bytes into a `0x20` stack buffer after a valid plasma signature is uploaded. This gives a saved `rbp` and return-address overwrite.

Because seccomp blocks the usual shell route, the final exploit uses an ORW chain:

- `open("/flag.txt", 0)`
- `read(fd, buf, len)`
- `write(1, buf, len)`

The stack is pivoted into writable global memory using the overflow, and the remote exploit used file descriptor `6` after `open()`.

Recovered flag:

`apoorvctf{c0sm1c_b4rr13rs_br0k3n_4nd_h4v0k_s3cur3d}`

### The Rite of the Blessings

The archive contained `flower.jpg`, `flower_processed.npy`, and helper scripts. The intended path was to recover a separate `3x3` convolution kernel for each RGB channel by solving the linear relationship between the original image and the processed tensor.

Recovered kernels:

- `R = [[1,-1,0],[-1,5,-1],[2,-1,0]]`
- `G = [[1,2,1],[-1,8,-1],[-3,-1,1]]`
- `B = [[-1,-4,1],[1,4,4],[-1,3,1]]`

The companion script required three integers. The intended values were the determinants of those matrices: `1`, `40`, and `35`.

Recovered flag:

`APOORVCTF{1_40_35}`

### Hefty Secrets

`base_model.pt` and `lora_adapter.pt` were PyTorch zip checkpoints. The base model contained several linear layers, while the adapter targeted `layer2.weight` via `layer2.lora_A` and `layer2.lora_B`.

Without loading the model in PyTorch, the checkpoint metadata and raw float storage were inspected directly. The important observation was that `W + B @ A` nearly canceled the original layer and produced values quantized to `0..255 / 255`, which strongly suggested an embedded grayscale image.

Reconstructing that `256x256` matrix as an image revealed the text:

`apoorvctf{l0r4_m3rg3}`

Submitted flag:

`APOORVCTF{l0r4_m3rg3}`

### Project Mirrorfall

The prompt pointed to a public Snowden archive mirror and specifically to the September 5, 2013 Bullrun classification guide. The target document was identified as:

`documents/2013/20130905-theguardian__bullrun.pdf`

Using the GitHub API for the latest commit affecting that exact file yielded:

- `X = 7d88323`

The PDF was then converted to text and Appendix A was inspected. In the ECI list, the relevant normalized word was:

- `Y = 0.0245` from the sentence-transformer embedding pipeline applied to `ambulant`

Recovered flag:

`APOORVCTF{7d88323_0.0245}`

## Web Exploitation

### Sugar Heist

The Spring Boot application exposed `/actuator`, which in turn revealed hidden admin routes including `/api/admin/flag`, `/api/admin/debug/config`, and `/api/admin/preview`.

The real bug chain was:

1. `POST /api/register` allowed mass assignment, so an attacker could self-register with `"role":"ADMIN"`.
2. `POST /api/login` returned a valid admin API token.
3. `POST /api/admin/preview` evaluated Thymeleaf expressions, giving SSTI.
4. `application.properties` was read to discover the true flag path `/app/flag.txt`.
5. The real flag file was read through SSTI with a simple path obfuscation to bypass the WAF.

Recovered flag:

`apoorvctf{sp3l_1nj3ct10n_sw33t_v1ct0ry_2026}`

### Typing Tycoon

The race service trusted client-controlled state too heavily:

- `/api/v1/race/sync` incremented progress even when the submitted word was wrong
- client-supplied `wpm` was trusted, and setting `wpm = 0` effectively slowed competing bots to near zero

The exploit path was to start a race, then repeatedly call the sync endpoint with junk words until the race completed.

Recovered flag:

`apoorvctf{typ1ng_f4st3r_th4n_sh3ll_1nj3ct10n}`

### Cosplayer's Delight

The exposed `/openapi.json` revealed undocumented endpoints: `/user/{username}`, `/my_votes`, `/vote_for`, and `/flag`.

A demo account was available. The critical flaw was that duplicate votes still leaked `recent_voters`, which made it possible to reconstruct a useful voter graph. Repeating vote queries across targets already voted on by the demo account showed that the standout voter was `victor`. His final five votes were:

`emilysys -> devon. -> judy -> dave -> alice`

Submitting that sequence to `/flag` returned the real flag.

Recovered flag:

`apoorvctf{gr4Ph_l34k5_r3v34l_v1cT0r5_l45t_v0t35_7f2a9}`

## Side Channels and Crypto

### TickTock

The password checker leaked information through timing. Each correct digit increased response time by roughly `0.8s`, which showed that the service compared digits left to right and exited early on mismatch.

The attack was simple:

1. Try `0` through `9` for the first digit.
2. Select the digit with the largest delay.
3. Extend the known prefix and repeat.

This recovered the full password:

`934780189098`

Submitting that password returned:

`apoorvctf{con5t4nt_tim3_or_di3}`

### Cable's Temporal Loop

This target combined a predictable LCG with a CBC padding oracle. `math_test(0)` revealed `b` directly, and several additional `math_test(d)` queries produced multiples of the hidden prime, allowing recovery of `p` with GCD calculations.

The harder part was that every decryption query also had to satisfy:

`int(ciphertext) mod p == next_lcg_state`

That constraint was bypassed by prepending one adjustable 16-byte block so the full ciphertext matched the required residue while leaving the target CBC structure intact. From there, the attack reduced to a state-aware padding oracle and the plaintext was recovered remotely in `7708` oracle queries.

Recovered flag:

`apoorvctf{T1m3_trAv3l_w1ll_n0t_h3lp_w1th_st4t3_crypt0}`

## Protocols, Services, and Misc

### Batman's Secret Batvault

The vault encryption transformed each `1` to `3` character chunk into a quartic polynomial whose roots were the encoded characters plus padding. Only polynomial coefficients were stored, so factoring each block recovered the original character multiset directly.

The solve path was:

1. Add single-character entries to derive the per-session root-to-character map.
2. Factor each block represented as:

   `x^4 + ax^3 + bx^2 + cx + d`

3. Identify the repeated padding root and the character root.
4. Decrypt all stored entries and reconstruct readable text from each anagram bag.

Recovered flag:

`apoorvctf{__gr3at_w0rk_p0lynomi4l_G0dS_67}`

### The Leaky Router

The provided protocol reference documented the RTUN frame format but omitted the parts that actually governed trust. Enumerating valid `TUNNEL_ID` and `INNER_PROTO` values showed that Node 2 and Node 3 were protected by authentication checks.

The critical bug was in `FLAGS`. The specification required bits `3` to `7` to remain zero, but the router accepted `FLAGS=0xff`. That special value bypassed authentication for both Node 2 and Node 3.

The final packet used:

- `VERSION = 1`
- `FLAGS = 0xff`
- `TUNNEL_ID = 3`
- `INNER_PROTO = 3`
- `PAYLOAD = GIVE_FLAG`

Recovered flag:

`apoorvctf{tun3l_v1s10n_byp4ss}`

### Riddler's Respite

This service had three menu stages. The first two returned flag-shaped strings that acted as passwords for the next stage, while the third returned the real flag.

The progression was:

1. Stage 1: exploit `mex(array) * xor(array)` with carefully chosen inputs to recover `apoorvctf{m3xtim3sx0r}`
2. Stage 2: recognize the tree function as the Wiener index and craft trees whose pairwise distance sums match the requested values, recovering `apoorvctf{sUm0fp4th3}`
3. Stage 3: identify the permutation function as the longest cycle length and submit direct cycles of the required sizes

Final recovered flag:

`apoorvctf{___CTF_m4r3_l3k3__CPF_000p3_ouwuo_}`
