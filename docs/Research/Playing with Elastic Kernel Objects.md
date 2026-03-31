---
title: Playing with Elastic Kernel Objects
slug: /Research/Playing-with-Elastic-Kernel-Objects
sidebar_position: 6
custom_edit_url: null
---

This write-up adapts research notes on elastic kernel objects into a cleaner long-form format for the `Research` section. The emphasis is on exploit mechanics, why the primitive matters, and how the ELOISE paper turns a hard manual hunt into a systematic process.

# ELOISE: Elastic Objects in Kernel Exploitation

![Elastic kernel object layout](/img/elastic-kernel-objects-layout.png)

I spent some time reading through the [ELOISE](https://dl.acm.org/doi/abs/10.1145/3372297.3423353) paper from CCS 2020 and wanted to write up my notes in a way that actually makes sense. The paper is dense, but the core idea is elegant once you get it.

## The Setup

Modern OS kernels are not easy to exploit. Over the years the kernel has accumulated a serious stack of protections:

```
┌─────────────────────────────────────────────────────────────┐
│                    KERNEL PROTECTION STACK                  │
├─────────────────────────────────────────────────────────────┤
│  KASLR    - Kernel Address Space Layout Randomization       │
│  SMEP     - Supervisor Mode Execution Prevention            │
│  SMAP     - Supervisor Mode Access Prevention               │
│  KPTI     - Kernel Page Table Isolation                     │
│  Stack Canary - Guard values to detect stack overflows      │
│  Heap Cookie  - Metadata integrity for heap allocations     │
│  W⊕R      - Memory regions are either Writable OR Readable  │
│  Freelist Randomization - Randomized heap freelist          │
└─────────────────────────────────────────────────────────────┘
```

Even if you find a memory corruption bug, you still need to climb a ladder before you can do anything useful:

```
STEP 1: Have a memory-corruption vulnerability (OOB write, UAF, DF)
           │
           ▼
STEP 2: Bypass KASLR → learn where kernel code is loaded
           │
           ▼
STEP 3: Defeat heap/stack cookies → validate exploit primitives
           │
           ▼
STEP 4: Achieve arbitrary read/write → full kernel control
           │
           ▼
STEP 5: Privilege escalation → root / full system compromise
```

Researchers had already shown that something called "elastic kernel objects" could help climb this ladder, but only on individual handpicked vulnerabilities. Nobody had asked whether this was broadly useful or just a lucky coincidence each time. ELOISE answers that question systematically across 40 vulnerabilities on Linux, FreeBSD, and XNU.

## What Even Is an Elastic Kernel Object?

An elastic kernel object is any kernel object that has three things going for it:

1. A **length field** somewhere inside it (`len`, `size`, `bmp_len`, whatever the developer called it)
2. That length field **controls how much of a buffer the kernel will read or write**
3. There is a **disclosure channel**, meaning some code path that copies data from that buffer back to userspace

```
┌─────────────────────────────────────────────────────────────────┐
│                     ELASTIC KERNEL OBJECT                       │
│                                                                 │
│   ┌──────────┬──────────┬──────────────────────────────────┐    │
│   │ header   │  LEN     │         buffer (elastic)         │    │
│   │ fields   │  field   │   actual size controlled by LEN  │    │
│   └──────────┴──────────┴──────────────────────────────────┘    │
│                  ↑                                              │
│            If an attacker                                       │
│            overwrites LEN,                                      │
│            the kernel will                                      │
│            read BEYOND the buffer!                              │
└─────────────────────────────────────────────────────────────────┘
```

The key insight is simple: if you can overwrite that length field with a larger number, the kernel will happily copy more bytes than it should to userspace. Those extra bytes come from whatever happens to sit next to your object in memory, which could include function pointers, cookies, or other sensitive values.

There are four ways this can be structured in practice.

### Variant 1: Buffer Inline

The most common case. The buffer lives inside the object itself.

```c
struct kernel_object {
    int  len;          // length field
    char buffer[MAX];  // elastic buffer INSIDE object
}

┌──────┬──────────────────────────────────┐
│ len  │ [===used===][......unused......] │
└──────┴──────────────────────────────────┘
         only `len` bytes should be read
```

### Variant 2: External Buffer with Direct Pointer

The buffer lives outside the object but there is a direct pointer to it.

```c
struct kernel_object {
    int   len;   // length field
    void *ptr;   // pointer to EXTERNAL buffer
}

Object:  ┌──────┬─────┐
         │ len  │ ptr─┼──────────────────────┐
         └──────┴─────┘                      │
                                             ▼
                            ┌───────────────────────┐
                            │  external buffer      │
                            │  [===len bytes===]    │
                            └───────────────────────┘
```

### Variant 3: External Buffer via Intermediate Object

A chain: object A points to object B, which points to the buffer.

```
Object A ──ptr──► Object B ──ptr──► Buffer C

┌───────┐         ┌───────┐         ┌─────────────────────┐
│  len  │         │  ptr  │─────────►  buffer data        │
│  ptr  ├────────►│       │         │  [len bytes]        │
└───────┘         └───────┘         └─────────────────────┘
```

### Variant 4: Length and Pointer in the Same Object

This is the dangerous one. When both the pointer and the length field live inside the same object, and an attacker can control both, you get arbitrary read anywhere in the kernel.

```c
struct kernel_object {
    void *ptr;  // attacker sets this to any kernel address
    int   len;  // attacker sets this to a large value
}

// Attacker sets ptr = target_address, len = large_value
// kernel reads from target_address for len bytes
// discloses arbitrary kernel memory to userspace
```

## A Real Example: `xfrm_replay_state_esn`

To make this concrete, here is the struct from the paper's main example.

**XFRM** is the Linux kernel's IPSec implementation. The name stands for "transform", referencing how IPSec transforms IP packets. If you want to go deeper on the protocol side, the relevant RFCs are:

- [RFC4301](https://www.rfc-editor.org/rfc/rfc4301): IPSec protocol definition
- [RFC4302](https://www.rfc-editor.org/rfc/rfc4302): Authentication Header (AH)
- [RFC4303](https://www.rfc-editor.org/rfc/rfc4303): Encapsulating Security Payload (ESP)

The IPSec protocol supports either 32-bit or 64-bit sequence numbers. The 64-bit variant is called Extended Sequence Numbers, ESN for short. The `xfrm_replay_state_esn` struct is the data structure the kernel uses to track ESN replay protection. `seq` and `seq_hi` together form a 64-bit inbound sequence number, `oseq` and `oseq_hi` form the outbound counterpart, `replay_window` defines how many past packets are remembered to detect duplicates, and `bmp[0]` is a flexible array acting as a dynamic bitmask where each bit corresponds to a received packet.

```c
struct xfrm_replay_state_esn {
    unsigned int    bmp_len;    // THE LENGTH FIELD
    __u32           oseq;
    __u32           seq;
    __u32           oseq_hi;
    __u32           seq_hi;
    __u32           replay_window;
    __u32           bmp[0];     // THE ELASTIC BUFFER
};
```

The whole struct is allocated as a single contiguous memory block. `bmp_len` tells the kernel how many 32-bit words are in the `bmp` bitmap. If you inflate `bmp_len`, the kernel reads past the bitmap into whatever object sits next to it in the slab.

```
Memory layout in kmalloc slab:

 xfrm_replay_state_esn         adjacent object
┌──────────────────────────────┬──────────────────────────────┐
│ bmp_len │ oseq │ seq │ ...   │ f_op pointer to              │
│  (LEN)  │      │     │ bmp[] │ ext4_file_operations         │
└──────────────────────────────┴──────────────────────────────┘
    ↑                                    ↑
    Attacker inflates bmp_len            This function pointer
    via vulnerability overwrite          is now readable
                                         reveals kernel base addr
                                         KASLR bypassed
```

## SLAB, SLUB and SLOB

Since we keep talking about slabs and caches, this is worth a quick detour.

**SLAB** is the original kernel object allocator, introduced in 1994 by Jeff Bonwick. The idea was object caching: frequently allocated objects like `task_struct` or `inode` get their own dedicated cache so that allocation is just grabbing a pre-initialized object rather than zeroing and setting up memory from scratch every time.

**SLUB** replaced SLAB as the default in kernel 2.6.23. It simplifies the design by eliminating the complex per-CPU queues and per-slab metadata, embedding metadata directly into unused objects instead. This makes it faster and easier to debug.

**SLOB** was the minimalist allocator for embedded and memory-constrained systems. It used a simple first-fit linked list with almost no overhead, sacrificing performance for a tiny footprint. It was removed from the kernel in v6.4.

The reason this matters for exploitation is that the allocator determines how objects get packed together in memory. When SLUB serves two objects from the same cache, they can end up in adjacent slots on the same slab page. That adjacency is exactly what heap overread exploits depend on. Knowing which cache (`kmalloc-64`, `kmalloc-192`, and so on) an object lands in tells you which other objects could be sitting right next to it.

## The Three Attack Capabilities

Before going into how ELOISE finds these objects automatically, it helps to understand exactly what these objects let you do.

| Capability | Mechanism | What It Bypasses |
| --- | --- | --- |
| **Heap Overread** | Inflate `len`, read adjacent slot | KASLR, heap cookie |
| **Stack Overread** | Inflate `len` of stack buffer, read up stack frame | Stack canary, return address |
| **Arbitrary Read** | Control both `ptr` and `len` in same object | Essentially everything |

### KASLR Bypass via Heap Overread

KASLR randomizes where the kernel loads in memory at boot. Without it, an attacker can hardcode jump targets. With it, they need to leak a pointer first to calculate the base address. The trick is that the kernel is full of objects containing function pointers, and those function pointers are compiled-in constants offset from the kernel base. If you can read one, you can subtract the known compile-time offset and recover where the kernel loaded.

```
BEFORE EXPLOITATION:
┌─────────────────────────────────────────────────────────┐
│  kmalloc-192 slab                                       │
│                                                         │
│  Slot 0 (victim): xfrm_replay_state_esn                 │
│  ┌─────────────────────────────┐                        │
│  │ bmp_len=5  │ bmp[5 words]   │                        │
│  └─────────────────────────────┘                        │
│                                                         │
│  Slot 1 (adjacent): file object                         │
│  ┌─────────────────────────────┐                        │
│  │ ... │ f_op=0xffffffff814abc │  kernel function ptr   │
│  └─────────────────────────────┘                        │
└─────────────────────────────────────────────────────────┘

AFTER OVERWRITING bmp_len:
┌─────────────────────────────────────────────────────────┐
│  Slot 0 (victim):                                       │
│  ┌─────────────────────────────┐                        │
│  │ bmp_len=256 │ bmp[5 words]  │   bmp_len inflated     │
│  └─────────────────────────────┘                        │
└─────────────────────────────────────────────────────────┘

Call recvmsg()
→ kernel copies bmp_len=256 bytes to user
→ reads 256 bytes starting from bmp[]
→ overreads into adjacent slot
→ userspace receives f_op = 0xffffffff814abc00

kernel_base = f_op - known_offset_of_ext4_file_operations
KASLR completely defeated
```

The attacker does not need to guess which object is adjacent. Using heap spray techniques they can fill the slab with objects they control, making it very likely that the slot next to the elastic object is something with a useful function pointer.

### Stack Canary Bypass via Stack Overread

The stack canary is a random value the compiler plants between local variables and the return address. If an overflow corrupts it, the kernel panics before returning. But if you can read it first, you can include the correct value in your exploit and the check passes as if nothing happened.

```
Stack frame layout:

High addresses
┌────────────────────────────────┐
│    return address              │
├────────────────────────────────┤
│    saved RBP                   │
├────────────────────────────────┤
│    stack canary (random)       │
├────────────────────────────────┤
│    local variables             │
├────────────────────────────────┤
│    elastic buffer[MAX]         │
│    (len field nearby)          │
└────────────────────────────────┘
Low addresses
```

If `len` is inflated beyond the actual buffer size, the copy reads up through the canary and the return address. Userspace receives the canary value and a kernel address in one shot. This matters because the return address is also a kernel pointer, so you bypass KASLR at the same time.

### Arbitrary Kernel Read

To understand this one it helps to know what the IDT is. The **Interrupt Descriptor Table** is a kernel data structure that tells the CPU what function to jump to when a specific interrupt fires. It is effectively the CPU's lookup table for exceptions, hardware interrupts, and software traps on x86.

```
IDT[0]   → Divide-by-zero handler   (#DE)
IDT[1]   → Debug exception          (#DB)
IDT[13]  → General Protection Fault (#GP)
IDT[14]  → Page Fault handler       (#PF)
IDT[32]  → Hardware IRQ 0 (timer)
IDT[128] → System call (int 0x80)
```

Now for the arbitrary read attack:

```
Normal operation:
  struct obj { void *ptr; int len; }
  kernel copies `len` bytes from `ptr` to user

Attacker controls both ptr AND len (same object):
  set ptr = 0xffffffff82001000   (IDT table address)
  set len = 0x1000               (read 4KB)
  kernel copies 4KB from IDT to userspace
  compute kernel base from IDT entries
  KASLR, stack canary, heap cookie all become known
```

This is more powerful than the heap overread case because you are not waiting for something interesting to land adjacent to your object. You get to choose the address directly.

### Heap Cookie (SLUB Freelist Encoding)

The heap cookie is how SLUB protects its freelist pointers. Free slots in a slab do not just store the raw address of the next free object. They XOR it with a secret and the slot's own address:

```c
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
                                 unsigned long ptr_addr) {
    return (void *)((unsigned long)ptr ^ s->random ^ ptr_addr);
}
```

The idea is that even if an attacker reads a free slot they cannot directly use the value they see as a pointer. But the elastic overread changes the game. When you overread into a free slot you get the encoded pointer. If you also know, or can infer, the slot's address, you only need to recover `s->random` to decode it.

## How ELOISE Works

ELOISE is a three-phase static analysis tool built on LLVM.

### Phase 1: Finding Elastic Object Candidates

The first challenge is that nested structs make length fields hard to find automatically. ELOISE recursively flattens nested structures so integer fields become visible to the analysis and can be treated as candidate length fields.

After flattening, ELOISE marks any struct with an integer field as a candidate. Then for each kernel allocation site (`kmalloc`, `kmem_cache_alloc`, and similar calls) it uses use-def chain analysis to figure out what type was just allocated. If that type is a candidate and the allocation does not require root, the object goes into the candidate set.

For cache membership, the logic is:

```
kmalloc(132, GFP_KERNEL):
  132 > kmalloc-128's max
  132 < kmalloc-256's max
  Object belongs to kmalloc-192

kmalloc(sizeof(base) + variable, GFP_KERNEL):
  exact size is not known statically
  object may belong to several general caches
  mark as cache-flexible
```

### Phase 2: Filtering for Disclosure Channels

Having a length field means nothing if the kernel never copies data through it back to userspace. Phase 2 filters the candidate set down to objects that actually have this path.

![Disclosure-channel filtering phase](/img/elastic-kernel-objects-disclosure-phase.png)

ELOISE looks for leaking anchors such as `copy_to_user`, `copyout`, `nla_put`, and `skb_put_data`. From each anchor it runs backward taint analysis on both the length argument and the data argument.

```c
FOR each anchor (fn, len_arg, data_arg):
    len_source = backward_taint(len_arg)
    if len_source is on HEAP:
        elastic_obj = object_containing(len_source)

        data_sources = backward_taint(data_arg)
        classify capability:
          stack source   -> STACK_OVERREAD
          heap field     -> HEAP_OVERREAD
          ptr+len same object -> ARBITRARY_READ
```

### Phase 3: Pairing with Vulnerabilities

The final phase takes a proof-of-concept program for a known vulnerability and asks whether that vulnerability can actually exploit any of the elastic objects the analysis found.

First, the PoC is run under GDB to determine which cache gets corrupted and what bytes the attacker can control. That becomes a capability model. Then, for each elastic object whose cache overlaps with the corrupted cache, ELOISE checks whether the vulnerability's writable region covers the object's length field offset. If it does, the combined path constraints are fed into Z3.

```
path_constraints AND vuln_constraints -> Z3.solve()

SAT   -> vulnerability can use the elastic object
UNSAT -> path is infeasible
```

![Backward taint analysis phase](/img/elastic-kernel-objects-taint-phase.png)

## CVE-2017-8890 in Detail

**Type:** Double Free  
**Subsystem:** Linux TCP/IP (`inet_csk_clone_lock`)  
**Affected:** Linux kernel earlier than `4.11`

ELOISE matches the vulnerability against `msg_msg`, where the important part is that the length field `m_ts` sits at an offset the bug can corrupt.

```c
struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;              // THE LENGTH FIELD
    struct msg_msgseg *next;
    void *security;
};
```

`msg_msg` is a particularly useful spray primitive because any unprivileged user can create message queues and send messages through `msgsnd`. The message payload gets allocated in the same slab as `msg_msg` itself, so you can fill a slab with these objects and get a predictable layout before triggering the vulnerability.

The exploit flow is straightforward:

1. Spray `msg_msg` objects into `kmalloc-64`.
2. Trigger the double-free.
3. Reclaim the freed slot with a crafted `msg_msg`.
4. Inflate `m_ts`.
5. Call `msgrcv()` and scan the oversized reply for a leaked kernel pointer.

## Choosing the Right Elastic Object

The ELOISE paper is strong on theory, but a practical question remains: how do you decide which elastic object to use in a real exploit chain?

The answer becomes concrete in the Steam Driver challenge from HTB UNI CTF Quals 2021. The driver exposes a use-after-free on an `engine_t` object that lives in `kmalloc-64`:

```c
typedef struct {
    id_t    id;
    uint8_t usage;
    char    engine_name[NAME_SZ];
    char   *logs;
} engine_t;
```

The critical observation is that `logs` sits at offset `0x30`. If a sprayed replacement object also places attacker-controlled data at offset `0x30`, then stale accesses through `engine->logs` become read or write primitives.

`msg_msg` fits that requirement unusually well:

- the reclaimed object lands in the same `kmalloc-64` cache
- the first `0x30` bytes are metadata
- the message body begins exactly where `engine_t->logs` used to be
- both `msgsnd()` and `msgrcv()` are available to unprivileged users

That means a stale dereference of `engine->logs` now reads a pointer embedded in the message body, which turns the bug into arbitrary read and arbitrary write.

## Results

Across Linux, FreeBSD, and XNU, the paper reports `74` confirmed elastic objects:

```
Heap overread potential: 70 / 74
Arbitrary read potential: 28 / 74
Stack overread potential:  5 / 74
No privilege required:    60 / 74
```

Out of `40` vulnerabilities tested, `27` could bypass KASLR and heap-cookie protection, and `8` could achieve arbitrary read.

The user study result is the part that really matters in practice. With ELOISE, one group bypassed KASLR on all five test vulnerabilities. Without it, another group got stuck at the elastic-object identification stage and made no progress after a full day. That is the strongest argument in the paper: manually finding these objects across a large kernel codebase is not realistic at scale.

## Defense: Cache Isolation

The proposed fix is clean. If elastic objects and general objects share the same slab cache, an attacker can arrange them adjacently and use one to corrupt or leak the other. If the allocator isolates elastic objects into separate caches, that adjacency disappears.

```c
#define __GFP_ISOLATE  ((__force gfp_t)___GFP_ISOLATE)

new_ldt = kmalloc(sizeof(*new_ldt), GFP_KERNEL | __GFP_ISOLATE);
```

After applying this defense and rerunning the pairing phase, almost all Linux vulnerabilities lost their elastic-object matches. The remaining cases were themselves elastic objects inside the isolated pool, which is a much narrower attack surface than the original design.

The main point is not that cache isolation solves every kernel exploitation problem. It is that it blocks a surprisingly effective bridge between ordinary memory corruption and the information leaks needed to defeat modern mitigations, while doing so at very low reported performance cost.
