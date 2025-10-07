---
title: "rev/cancers 🦀 - Securinets CTF Quals 2025"
date: 2025-10-06
draft: false
description: "Write up for the cancers rev chal"
tags: ["CTF", "rev", "windows", "x86"]
showTableOfContents: true
---

This was a fun challenge that had a mix of unpacking, PRNG stuff, and encryption.

## Challenge Description
This ugly crab ate all of my files and is asking me to pay a ransom. Since you guys are good at hacking can you recover my most precious file, it's called flag.txt? 👉👈

BEWARE IT CAN EAT YOUR FILES AS WELL
>zip password: cancers

Author: 0xjio
Files: [cancers.zip](/writeups/cancers/cancers.zip)

## Solution

### Initial Analysis
Unzipping the given zip file, we're given two files, `cancers.exe` and `flag.txt.crs`
Running `file` on the exe tells its upx packed.
```
❯ file cancers.exe
cancers.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386, UPX compressed, 3 sections
```
So we can unpack like this.
```
upx -d cancers.exe
```

The other file `flag.txt.crs` intially seems the flag but encrypted, it's also created by the executable.
```
❯ xxd flag.txt.crs
00000000: 56e1 5cf5 9f92 676d 7b81 5148 d03a 1b32  V.\...gm{.QH.:.2
00000010: 270f 67aa fcd7 c03e 8b7e fd6b 934d 720e  '.g....>.~.k.Mr.
00000020: be48 aa54 f003 324f d62f 66a9 ac38 f38c  .H.T..2O./f..8..
00000030: 4cf8 905e 1f47 eace c42e cc34 b441 d6a4  L..^.G.....4.A..
...
00000530: e836 a491 f61c 1b57 6698 5117 6a17 9180  .6.....Wf.Q.j...
00000540: 44a4 fdc1 5a86 db41 1516 707f 37d0 56e0  D...Z..A..p.7.V.
```

If we delete the original flag.txt.crs, create our own `flag.txt` (empty for now), and then run the program, we're given a new `flag.txt.crs` that looks like this.
```
❯ xxd flag.txt.crs
00000000: 26a1 60a2 3210 aa2f f36e c965 7697 1bcb  &.`.2../.n.ev...
00000010: 7d94 137c 4a2a 9503 9d20 55d6 508a 355b  }..|J*... U.P.5[
```
You can probably get some more information from this file at this point by messing with the input flag, however I didn't really do this.

Loading the program into ghidra, the decompilation doesn't tell us much. There are a bunch of Windows MFC API calls, but I personally couldn't really tell what was happening from looking at it, but knowing that it opens the files `flag.txt` and `flag.txt.crs`, those strings should be in the binary somewhere.

But they're not, which hints that there's more unpacking.
Viewing the process through process explorer also tells us that it launches another exe at some point.
![second process](/writeups/cancers/process2.png)

You can also just keep on stepping through the program until you find something, or just break on kernel32 calls.

### Part 1: The Second Unpacking
With this info, we can search for referencse to functions like CreateProcessW or VirtualAlloc in ghidra.
![kernel32calls](/writeups/cancers/kernel32_funcs.png)
These all have references in FUN_00405a10. Looking at `CreateProcessW`'s call, it starts another process running `cancers.exe`, however it is not fully loaded yet.
Breaking on `VirtualAllocEx`, we can check the memory map in our debugger for areas marked as `ERW-` (execute + read + write).
Honestly I'm not exactly sure what happens between this and the rest of the code 
![memmap](/writeups/cancers/memmap.png)
If you're unsure which one is the unpacked program, you can check by just dumping all of them. If you do that you'll notice that one of them is actually our original `cancers.exe`, and another is a new program written in rust🦀. I also noticed while writing this writeup that the correct one's address is in `ESI`. Honestly there's probably a better way to unpack it but that's what I did.

Interestingly enough, our dumped binary is just a PE, so we can run it on it's own too, making future debugging easier.

### Part 2: Crustacean 🦀
Running strings on our new program, we see that it has `flag.txt` and `flag.txt.crs`, meaning this is likely what opens/creates those files. Searching for references to this in ghidra leads us to `FUN_00af1750`. It's being passed into a function, which means that that is opening the file. The handle to that file is then read from.

```c
  FUN_00af73f0((undefined8 *)&local_220,(byte *)&local_500,"flag.txtsrc\\main.rs",8); // open file
  if ((byte)local_220 != 4) {
    *param_1 = 4;
    if (2 < (byte)local_220) {
      local_590 = (LPVOID)*local_21c;
      local_580 = (undefined4 *)local_21c[1];
      if ((code *)*local_580 != (code *)0x0) {
        local_18 = 6;
        (*(code *)*local_580)(local_590);
      }
      if (local_580[1] != 0) {
        FUN_00af2ae0(local_590,local_580[1],local_580[2]);
      }
      FUN_00af2ae0(local_21c,0xc,4);
    }
    goto LAB_00af22c0;
  }
  SVar66 = 0;
  local_18 = 0;
  local_594 = local_21c;
  FUN_00af7300((char *)&local_500,&local_594,(SIZE_T *)&stack0xfffffa60); // read file to local_594
```


#### PRNG
After this we can clean up the layout of some locals to see that we have a `uint[4]` array set to some intial values. This is then passed into `FUN_00af1580` that transforms these values (we'll look into that later).

```c
  local_564[0] = 0x11223344;
  local_564[1] = 0xabacadae;
  local_564[2] = 0x1c0de1c0;
  local_564[3] = 0x13372025;
  FUN_00af1580(local_564,0);
  local_310 = FUN_00afa780();//GetTime
  FUN_00afa7b0(&local_500,(uint *)&local_310,0xd53e8000,0x19db1de);//convert to seconds
```

`FUN_00afa780` gets the system time, and `FUN_00afa7b0` I think transforms it to unix time.
```c
undefined8 FUN_af40a780(void) {
  undefined4 local_c;
  undefined4 local_8;
  local_c = 0;
  local_8 = 0;
  GetSystemTimePreciseAsFileTime(&local_c);
  return CONCAT44(local_8,local_c);
}
```

While writing this writeup I decompiled the program again in ghidra and got some wierd decompilation that was actually missing some of the program flow.

```c
  FUN_00afa7b0(&local_500,(uint *)&local_310,0xd53e8000,0x19db1de);
  if (((byte)local_500 & 1) != 0) {
    local_21c = local_4f4;
    local_220 = local_4f8;
    local_218 = local_4f0;
    FUN_00b0d880("called `Result::unwrap()` on an `Err` valueC:\\Users\\jihed\\.rustup\\toolchains\\ stable-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\slice.rs"
                 ,0x2b,&local_220,&DAT_00b0e2d8,&DAT_00b0e3e8);
    goto LAB_00af23a1;
  }

    /**
        THERE SHOULD BE SOMETHING HERE BUT THERE WASNT WHEN I REDECOMPILED IDK WHY
    **/

                    /* WARNING: Read-only address (ram,0x00b0e1d0) is written */
  local_510[0] = local_564;
  local_510[1] = uStack_560;
  local_510[2] = uStack_55c;
  local_510[3] = uStack_558;
  iVar65 = *(int *)((int)local_510 + (local_4f8 * 0x343fd + 0x29ec3U >> 0xe & 0xc));
```

Anyways, the next thing that happens after getting the time is this. You can ignore some of the names, just note that there's a bunch of stuff going on here. Notably, it's changing the value of *rand*, and then xor'ing the flag. The state is also being changed in FUN_00af1580.
```c
  if (flag_len == (undefined4 *)0x0) {
    time = puStack_4f8;
    puVar37 = (undefined4 *)0x0;
  }
  else {
    local_5a8 = puStack_4f8;
    local_590 = flag_len;
    flag_ptr = local_59c;
    do {
      local_580 = (undefined4 *)state[3];
      uVar35 = state[0] << 0xb ^ state[0];
      uVar35 = uVar35 >> 8 ^ state[3] >> 0x13 ^ uVar35 ^ state[3];
      uVar38 = (uVar35 >> 0x10 ^ uVar35) * 0x45d9f3b;
      rand = (uVar38 >> 0x10 ^ uVar38) * 0x3848f357;
      *flag_ptr = *flag_ptr ^ (byte)((uint)rand >> 0x10) ^ (byte)rand;
      flag_ptr = flag_ptr + 1;
      local_5b0 = (undefined4 *)state[2];
      uVar38 = state[1] << 0xb ^ state[1];
      state[0] = state[2];
      uVar38 = uVar38 >> 8 ^ uVar38 ^ uVar35;
      state[1] = state[3];
      state[3] = uVar35 >> 0x13 ^ uVar38;
      uVar38 = (uVar38 >> 0x10 ^ state[3]) * 0x45d9f3b;
      uVar38 = (uVar38 >> 0x10 ^ uVar38) * 0x3848f357;
      state[2] = uVar35;
      FUN_00af1580(state,uVar38 & 0x7fffffff ^ uVar38 >> 0x10);
      local_590 = (undefined4 *)((int)local_590 - 1);
      time = local_5a8;
      puVar37 = flag_len;
    } while (local_590 != (undefined4 *)0x0);
  }
```

After this is something else that was missing when i re-decompiled.
```c
  rand = *(int *)((int)local_510 + ((int)time * 0x343fd + 0x29ec3U >> 0xe & 0xc));
  flag_ptr = local_59c;
  for (; puVar37 != (undefined4 *)0x0; puVar37 = (undefined4 *)((int)puVar37 - 1)) {
    rand = rand * 0x343fd + 0x269ec3;
    *flag_ptr = *flag_ptr ^ (byte)((uint)rand >> 0x10);
    flag_ptr = flag_ptr + 1;
  }
```

`rand = rand * 0x343fd + 0x269ec3;` is MSVC's random LCG, and the time is the seed in this case. This is the same as calling srand(time) and then repeatedly calling rand().

The first line indexes our uint[4] state by generating a random number 0, 4, 8, 12. Each byte of the flag is also getting xor'ed with the bottom byte of the random value.


#### AES
Now comes some crazy inlining. Ghidra shows something like the following.

```c
  auVar40._0_4_ = rand * 0x40a25379 + 0x81195ce6U >> 0x10;
  auVar40._4_4_ = rand * 0x56b02995 + 0x5039a011U >> 0x10;
  auVar40._8_4_ = rand * 0x43ba1741 + 0x3e314290U >> 0x10;
  auVar40._12_4_ = rand * -0x173e01c3 + 0x22f11713U >> 0x10;
  local_590 = (undefined4 *)(rand * -0x3f8068e3 + -0x572d7d95);
  uStack_58c = 0;
  uStack_588 = 0;
  uStack_584 = 0;
  auVar44._0_4_ = rand * 0x67fbeea9 + 0x77948382U >> 0x10;
  auVar44._4_4_ = rand * 0x7f6c1805 + 0x96dd9c3dU >> 0x10;
  auVar44._8_4_ = rand * -0x7fd3f40f + 0xedc4fe0cU >> 0x10;
  auVar44._12_4_ = rand * 0x567ae02d + 0x8476d49fU >> 0x10;
  local_580 = (undefined4 *)(rand * 0xc287375 + 0x20ad96a9);
  uStack_57c = 0;
  uStack_578 = 0;
  uStack_574 = 0;
  auVar48._0_4_ = rand * 0xf56bad9 + 0x2e15555eU >> 0x10;
  auVar48._4_4_ = (uint)local_580 >> 0x10;
  auVar48._8_4_ = rand * -0xb6f465f + 0x7e1dbec8U >> 0x10;
  auVar48._12_4_ = (uint)local_590 >> 0x10;
  auVar54._0_4_ = rand * -0x560397f7 + 0x1e278e7aU >> 0x10;
  auVar54._4_4_ = rand * 0x45c82be5 + 0xd2f65b55U >> 0x10;
  auVar54._8_4_ = rand * -0x2200afaf + 0x98520c4U >> 0x10;
  auVar54._12_4_ = rand * 0x284a930d + 0xa2974c77U >> 0x10;
  auVar40 = auVar40 & _DAT_00b0e1d0;
  auVar44 = auVar44 & _DAT_00b0e1d0;
  auVar48 = auVar48 & _DAT_00b0e1d0;
  auVar54 = auVar54 & _DAT_00b0e1d0;
  sVar25 = auVar44._0_2_;
  bVar2 = (0 < sVar25) * (sVar25 < 0x100) * auVar44[0] - (0xff < sVar25);
  sVar25 = auVar44._4_2_;
  bVar3 = (0 < sVar25) * (sVar25 < 0x100) * auVar44[4] - (0xff < sVar25);
  sVar25 = auVar44._8_2_;
  cVar4 = (0 < sVar25) * (sVar25 < 0x100) * auVar44[8] - (0xff < sVar25);
  sVar25 = auVar44._10_2_;
    ....
    ....
  wtf.key._0_4_ =
       CONCAT13((0 < sVar25) * (sVar25 < 0x100) * cVar12 - (0xff < sVar25),
                CONCAT12((0 < sVar32) * (sVar32 < 0x100) * cVar11 - (0xff < sVar32),
                         CONCAT11((bVar10 != 0) * (bVar10 < 0x100) * bVar10 - (0xff < bVar10),
                                  (bVar9 != 0) * (bVar9 < 0x100) * bVar9 - (0xff < bVar9)))) ^
       0x25252525;
  wtf.key._4_4_ =
       CONCAT13((0 < sVar27) * (sVar27 < 0x100) * cVar16 - (0xff < sVar27),
                CONCAT12((0 < sVar26) * (sVar26 < 0x100) * cVar15 - (0xff < sVar26),
                         CONCAT11((bVar14 != 0) * (bVar14 < 0x100) * bVar14 - (0xff < bVar14),
                                  (bVar13 != 0) * (bVar13 < 0x100) * bVar13 - (0xff < bVar13)))) ^
       0x25252525;
  wtf.key._8_4_ =
       CONCAT13((0 < sVar28) * (sVar28 < 0x100) * cVar34 - (0xff < sVar28),
                CONCAT12((0 < sVar31) * (sVar31 < 0x100) * cVar4 - (0xff < sVar31),
                         CONCAT11((bVar3 != 0) * (bVar3 < 0x100) * bVar3 - (0xff < bVar3),
                                  (bVar2 != 0) * (bVar2 < 0x100) * bVar2 - (0xff < bVar2)))) ^
       0x25252525;
  wtf.key._12_4_ =
       CONCAT13((0 < sVar30) * (sVar30 < 0x100) * cVar8 - (0xff < sVar30),
                CONCAT12((0 < sVar29) * (sVar29 < 0x100) * cVar7 - (0xff < sVar29),
                         CONCAT11((bVar6 != 0) * (bVar6 < 0x100) * bVar6 - (0xff < bVar6),
                                  (bVar5 != 0) * (bVar5 < 0x100) * bVar5 - (0xff < bVar5)))) ^
       0x25252525;
```

The important thing to note here is the `x * a + b`. This is done 16 times here, getting one byte for each time this happens, this is then packed into 16 bytes. This is easier to see happening while debugging. I've taken some screenshots to display what I saw when doing this.

![keyivgen](/writeups/cancers/keyivgen.png)

It does this 3 times with different sets of multiplers and adds. The last one is also xor'ed with 0x37 instead of 0x25. These values are then passed in to a function that makes use of the `aeskeygenassist` instruction, as well `aessimc`, to create the round keys for encryption and decryption. It creates 15 for each of them, meaning we're doing AES-256 (15 rounds). With this info, we know that we have to have a known IV to decrypt. Taking a look at our custom *flag.txt.crs* (not the original), and comparing with the values found when debugging, we can see that the last value matches up.

![keyivgenned](/writeups/cancers/keyivgenned.png)
![keyivcrs](/writeups/cancers/keyivcrs.png)

As you can see, the 3rd set of 16 bytes is the same as the first line in your `flag.txt.crs`, meaning that is the known IV.

Now in python, trying to decrypt using the first 32 bytes generated from the program as our key works, and the IV as the first 16 bytes of the file works to decrypt the rest of the bytes in our file.

### Part 3: Decryption

#### Getting The Key
The problem we face now is getting the key that was used to encrypt the flag. However, we can brute force the seed used to generate the key by just trying different seeds until we get an IV that matches our target.


```c
struct crypto {
    uint8_t key[32];
    uint8_t IV[16];
};

uint32_t multipliers[] = {
    0x40a25379, 0x56b02995, 0x43ba1741, -0x173e01c3,
    0x67fbeea9, 0x7f6c1805, -0x7fd3f40f, 0x567ae02d,
    0xf56bad9, 0xc287375, -0xb6f465f, -0x3f8068e3,
    -0x560397f7, 0x45c82be5, -0x2200afaf, 0x284a930d,
    0x4fa110b9, 0xbb8f1d5, -0x2d6f417f, 0x366b087d,
    -0x54cd3817, -0x2cc373bb, 0x405baf31, -0x58f70993,
    0x3c78f019, 0x3aa6d3b5, 0x1b6698e1, -0x46f506a3,
    -0x3806c6b7, -0x78d947db, -0x241b546f, 0x2c97814d,
    0x41cfddf9, 0xb718a15, -0x5b680a3f, 0x50c262bd,
    0x4224b129, 0xc1bd085, -0x4f611d8f, -0x3663a353,
    0x35713559, 0x11e303f5, 0x23430821, 0x7cc2ab9d,
    -0x1b88e577, 0x45421465, -0x52c692f, 0x807bf8d,
};

uint32_t adds[] = {
    0x81195ce6U, 0x5039a011U, 0x3e314290U, 0x22f11713U,
    0x77948382U, 0x96dd9c3dU, 0xedc4fe0cU, 0x8476d49fU,
    0x2e15555eU, 0x20ad96a9, 0x7e1dbec8U, -0x572d7d95,
    0x1e278e7aU, 0xd2f65b55U, 0x98520c4U, 0xa2974c77U,
    0xfe1682f6U, 0x898e6de1U, 0x824e1920U, 0x8348d363U,
    0x852b5492U, 0xf0d1690dU, 0x8c0d79cU, 0xa5fd87efU,
    0x7c93616eU, 0xd497b279U, 0xe532ab58U, 0xc819fcbbU,
    0xe6ad658aU, 0x8bb51625U, 0xb9583054U, 0xd1f05dc7U,
    0x50689d06U, 0xafb45fb1U, 0xf98783b0U, 0x9d9ad3b3U,
    0x9aded9a2U, 0xee3f19ddU, 0x45df052cU, 0x7b6d3f3fU,
    0xb149e17eU, 0x30a87249U, 0x8363abe8U, 0xf35d3b0bU,
    0x489b709aU, 0xc20b34f5U, 0x52f513e4U, 0x5c3bf317U,
};

void generate_crypto(struct crypto *key_and_iv, uint32_t rand) {

    uint32_t temp[48];
    for (int i = 0; i < 48; i++) {
        uint32_t result = (rand * multipliers[i] + adds[i]) >> 0x10;
        temp[i] = (uint32_t)result & 0xff;
    }

    for (int i = 0; i < 4; i++) {
        int idx = i*4;
        int top = 16, bot = 0;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx+3] ^ 0x25;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x25;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x25;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x25;
    }

    for (int i = 4; i < 8; i++) {
        int idx = i*4;
        int top = 32, bot = 16;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx+3] ^ 0x25;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x25;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x25;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x25;
    }

    for (int i = 8; i < 12; i++) {
        int idx = i*4;
        int top = 48, bot = 32;
        int fill_idx = top - idx + bot;
        key_and_iv->key[fill_idx - 1] = (uint8_t)temp[idx + 3] ^ 0x37;
        key_and_iv->key[fill_idx - 2] = (uint8_t)temp[idx+2] ^ 0x37;
        key_and_iv->key[fill_idx - 3] = (uint8_t)temp[idx+1] ^ 0x37;
        key_and_iv->key[fill_idx - 4] = (uint8_t)temp[idx+0] ^ 0x37;
    }
}

...

struct crypto key_and_iv = {};
for (int seed = 0; seed < 0xffffffff; seed ++) {
    generate_crypto(&key_and_iv, seed);
    if (memcmp(key_and_iv.IV, target_key, 16) == 0) {
        printf("rand=0x%08x, key=", seed);
        for (int i = 0; i < 32; i++) {
            printf("%02x", key_and_iv.key[i]);
        }
        printf("\n");
        break;
    }
}
```

This C program does exactly that. Note: it probably would've been way easier to hijack the exe to generate the key but I'd already done this.

So, our target IV is `56e15cf59f92676d7b815148d03a1b32` (from `flag.txt.crs`).5
```
❯ xxd ../flag.txt.crs | head -n 1
00000000: 56e1 5cf5 9f92 676d 7b81 5148 d03a 1b32  V.\...gm{.QH.:.2
❯ gcc solve.c -o solve && ./solve 56e15cf59f92676d7b815148d03a1b32
rand=0x0013d99b, key=f078177e309d2f74d32e571c3b14434ba9d9d9d90958bf208c5a4241a670daaa
```

This actually runs really fast probably <300ms.

Now with our key:
```py
flag_encrypted = open(sys.argv[1], 'rb').read()
iv = flag_encrypted[0:16]
ciphertext = flag_encrypted[16:]
print("iv=", iv.hex())

key = bytes.fromhex("f078177e309d2f74d32e571c3b14434ba9d9d9d90958bf208c5a4241a670daaa")
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = bytearray(unpad(decrypted_padded, AES.block_size))
```

This does not throw an exception which means it worked!
Now for the final part.

#### XOR Finale

Remember, before the AES, the flag was xored based on some the uint[4] state values. I put these into python to make life harder for myself (had to add A TON of `& 0xffffffff`).
```
def transform(param_1: list[int], param_2: int):
    uVar2 = (param_2 * -0x61c8864f) & 0xffffffff
    uVar5 = (param_2 << 0x10 & 0xffffffff) | (param_2 >> 0x10 & 0xffffffff);
    uVar3 = ((param_2 ^ 0xf00dabcd) << 0xb & 0xffffffff) ^ param_2 ^ 0xf00dabcd;
    uVar4 = (((0x13371346 - param_2) & 0xffffffff) * 0x800 & 0xffffffff) ^ ((0x13371346 - param_2) & 0xffffffff);
    uVar1 = (param_2 * -0x44327800 & 0xffffffff) ^ uVar2;
    uVar2 = ((uVar3 >> 8) ^ (uVar2 >> 0x13) & 0xffffffff) ^ uVar2 ^ uVar3;
    uVar5 = (uVar5 << 0xb & 0xffffffff) ^ uVar5;
    uVar6 = uVar5 >> 8 ^ uVar5 ^ uVar2;
    uVar5 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb & 0xffffffff ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb & 0xffffffff ^ uVar3;
    uVar4 = uVar1 ^ uVar4 >> 0x13;
    uVar5 = uVar7 >> 8 ^ uVar7 ^ uVar4;
    uVar4 = uVar4 << 0xb & 0xffffffff ^ uVar4;
    uVar1 = uVar5 ^ uVar1 >> 0x13;
    uVar2 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb & 0xffffffff ^ uVar1;
    uVar5 = uVar2 ^ uVar5 >> 0x13;
    uVar6 = uVar3 >> 8 ^ uVar3 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar7 = uVar6 ^ uVar2 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar7;
    uVar7 = uVar7 << 0xb & 0xffffffff ^ uVar7;
    uVar2 = uVar3 ^ uVar6 >> 0x13;
    uVar4 = uVar1 >> 8 ^ uVar1 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar3 = uVar4 ^ uVar3 >> 0x13;
    uVar1 = uVar5 >> 8 ^ uVar5 ^ uVar3;
    uVar3 = uVar3 << 0xb & 0xffffffff ^ uVar3;
    uVar5 = uVar1 ^ uVar4 >> 0x13;
    uVar7 = uVar7 >> 8 ^ uVar7 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar1 = uVar7 ^ uVar1 >> 0x13;
    uVar4 = uVar2 >> 8 ^ uVar2 ^ uVar1;
    uVar1 = uVar1 << 0xb & 0xffffffff ^ uVar1;
    uVar2 = uVar4 ^ uVar7 >> 0x13;
    uVar7 = uVar3 >> 8 ^ uVar3 ^ uVar2;
    uVar2 = uVar2 << 0xb & 0xffffffff ^ uVar2;
    uVar4 = uVar7 ^ uVar4 >> 0x13;
    uVar3 = uVar5 >> 8 ^ uVar5 ^ uVar4;
    uVar4 = uVar4 << 0xb & 0xffffffff ^ uVar4;
    uVar5 = uVar3 ^ uVar7 >> 0x13;
    uVar7 = uVar1 >> 8 ^ uVar1 ^ uVar5;
    uVar5 = uVar5 << 0xb & 0xffffffff ^ uVar5;
    uVar6 = uVar7 ^ uVar3 >> 0x13;
    uVar1 = uVar2 >> 8 ^ uVar2 ^ uVar6;
    uVar2 = uVar1 ^ uVar7 >> 0x13;
    uVar3 = uVar4 >> 8 ^ uVar4 ^ uVar2;
    uVar1 = uVar3 ^ uVar1 >> 0x13;
    param_1[3] = (uVar5 >> 8 ^ uVar5 ^ uVar1 ^ uVar3 >> 0x13) & 0xffffffff;
    param_1[0] = uVar6 & 0xffffffff;
    param_1[1] = uVar2 & 0xffffffff;
    param_1[2] = uVar1 & 0xffffffff;
    return param_1

def prng_xor_1(state, flag):
    for i, c in enumerate(flag):
        uVar36 = state[0] << 0xb & 0xffffffff ^ state[0];
        uVar36 = uVar36 >> 8 ^ state[3] >> 0x13 ^ uVar36 ^ state[3];
        uVar40 = (uVar36 >> 0x10 ^ uVar36) * 0x45d9f3b & 0xffffffff;
        randthing = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357 & 0xffffffff;
        flag[i] = flag[i] ^ ((randthing >> 0x10) & 0xff) ^ (randthing & 0xff);
        #flag_ptr = flag_ptr + 1;
        uVar40 = state[1] << 0xb  & 0xffffffff ^ state[1];
        state[0] = state[2];
        uVar40 = uVar40 >> 8 ^ uVar40 ^ uVar36;
        state[1] = state[3];
        state[3] = uVar36 >> 0x13 ^ uVar40;
        uVar40 = (uVar40 >> 0x10 ^ state[3]) * 0x45d9f3b & 0xffffffff;
        uVar40 = (uVar40 >> 0x10 ^ uVar40) * 0x3848f357 & 0xffffffff;
        state[2] = uVar36;
        state = transform(state,uVar40 & 0x7fffffff ^ uVar40 >> 0x10);
        puVar39 = len(flag);
    return flag

def prng_xor_2(rand, flag):
    for i in range(len(flag)):
        rand = ((rand * 0x343fd & 0xffffffff) + 0x269ec3) & 0xffffffff
        flag[i] = flag[i] ^ rand >> 0x10 & 0xff
    return flag, rand
```

So now we can try and undo the xor operations (technically just redo the same ones). This is simple since the only random part here is choosing the random state as the seed, but since there's only four of them we can just try each one.
```py
state = [
    0x11223344,
    0xabacadae,
    0x1c0de1c0,
    0x13372025
]

state = transform(state, len(decrypted))
xored_1 = prng_xor_1(state, decrypted.copy())
for i in range(len(state)):
    decrypted_p2, rand = prng_xor_2(state[i], xored_1.copy())
    try:
        print(decrypted_p2.decode())
    except Exception:
        continue
```

Running this we get the flag.
```
❯ python3 crypt.py ../flag.txt.crs
iv= 56e15cf59f92676d7b815148d03a1b32

                      e$$$      .c.
                    4$$$$     ^$$$$$.
                    $$$$        $$$$$.
                   .$$$$         $$$$$
                z$$$$$$$$       $$$$$$b
               $$$$$$""          *$$$$$$.
               $$$$$                $$$$$r
      \        $$$*     dc    ..    '$$$$b
      4       $$$F      $F    $%     $$$$$       4
      'r     4$$$L  .e$$$$$$$$$$bc    $$$$r      $
       $.    '$$$$z$$$$$$$$$$$$$$$$$..$$$$$     z$
       $$$c   $$$$$$$$$$$$$$$$$$$$$$$$$$$$F  .d$$*
         "$$$. $$$$$$$$$$$$$$$$$$$$$$$$$$P z$$$"
            "$$b$$$$$$$$$$$$$$$$$$$$$$$$$d$$*
               "$$$$$$$$$$$$$$$$$$$$$$$$$P"
   ^         .d$$$$$$$$$$$$$$$$$$$$$$$$"
    "e   .e$$$$*"$$$$$$$$$$$$$$$$$$$$$$$$$$e..  e"
     *$$$$P"     ^$$$$$$$$$$$$$$$$$$$$P ""**$$$$
      *"          $$$$$$$$$$$$$$$$$$$P
                .$$"*$$$$$$$$$$$$P**$$e
               z$P   J$$$$$$$$$$$e.  "$$c     .
              d$" .$$$$$$*""""*$$$$$F  "$$. .P
       ^%e.  $$   4$$$"          ^$$     "$$"
          "*$*     "$b           $$"       ^
                     $r          $
                      ".        $

            ===   Author: ~~ 0xjio ~~   ===
            ---  https://jihedkdiss.tn  ---

Securinets{N0T_oNly_RuSt_BuT_Y0u'R3_4ls0_g00d_@T_UNP4CK1NG}
```

### Solution Scripts
[solve.c (key bruteforce)](/writeups/cancers/solve.c)

[crypt.py (python decryption)](/writeups/cancers/crypt.py)


