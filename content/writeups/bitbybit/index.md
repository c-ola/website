---
title: "crypto/Bit by Bit - PatriotCTF 2024"
date: 2024-09-23
draft: false
description: "Write up for the Bit by Bit challenge from PatriotCTF 2024"
tags: ["ctf", "crypto"]
showTableOfContents: true
---
I'm not very experienced with crypto chals, so this was fun to figure out.

## Description
I heard one-time pads are unbreakable.\
Files: [`transmit.py`](/writeups/bitbybit/transmit.py) and [`out.txt`](/writeups/bitbybit/out.txt)

## Solution
We are given `out.txt` which is the output of `transmit.py`, a text encrypted using one time pad and then encoded into hex.\
We first write the following function to read the encoded output:
```py
def decrypt(msg, key):
    iv = 0
    chunks = [msg[i:i+32] for i in range(0,len(msg) - 32, 32)]
    dec = b''
    i = 0
    for chunk in chunks:
        iv = (iv+1) % 255
        curr_k = key+iv
        enc = int(chunk, 16) ^ curr_k
        dec += enc.to_bytes(16)
        print(i, ":", enc.to_bytes(16))
        i += 1
    return dec
```

Running this with `out.txt` as `msg` prints the following:
```
0 : b'Chap\xda\xa893\xa1ew\x82\x0c\x9a\xbbn'
1 : b'igma\xda\xa4(3\xd3*G\x8fc\xf3\x90 '
2 : b'a di\xc3\xa123\xfc,W\xca\x1b\xd5\x91m'
3 : b' in \xca\xa2<}\xe4*T\x84I\xf9\x96i'
4 : b'cago\x82\xed\x0eg\xf8$M\xcaK\xf9\x97p'
5 : b'her"\x8e\x9f.j\xfe*O\x8e\x1a\x9a\x8da'
6 : b't hu\xc0\xae#v\xf4eL\x9c\x0c\xc8\xdeh'
7 : b'is c\xc1\xa0;f\xe4 Q\xc6I\xce\x96e'
8 : b' glo\xd9\xed-a\xff(\x03\x9e\x01\xdf\xdem'
9 : b'onit\xc1\xbfkp\xf16W\x83\x07\xdd\xdea'
10 : b' blu\xc7\xbe#3\xf80F\xca\x08\xd9\x8co'
11 : b'ss h\xc7\xbekw\xf51F\x98\x04\xd3\x90e'
12 : b'd fa\xcd\xa8e3\xc4-F\xca\n\xd6\x91c'
13 : b'k on\x8e\xb9#v\xb02B\x86\x05\x9a\x8ai'
14 : b'cked\x8e\xbd*`\xe4eN\x83\r\xd4\x97g'
15 : b'ht, \xcc\xb8?3\xd51K\x8b\x07\x9a\x8ea'
16 :b'id n\xc1\xed&z\xfe!\r\xca!\xdf\xdew'
...
```
This goes on for 368 lines.
We can see that the first 4 letters of each chunk were not encrypted, meaning we can guess what word they would be. For example; "Chap" -> "Chapter 1 ".

Since the key is also being repeated every 256 chunks, we can figure out the key using some xor math and quirks of the english language.

### XOR Math Explanation
A one time pad is a simple xor with a key of the same length as the plaintext.\
`p ^ k = c`

Given two ciphertexts `c1, c2`, unknown plaintexts `p1, p2` and an unkown key `k`:\
`p1 ^ k = c1`\
`p2 ^ k = c2`

Then:\
`c1 ^ c2 = p1 ^ p2 = x`

If we can guess some of the characters `p1'` of the plaintext based on other adjacnet characters, we can then determine the key by going backwards.

`p2' = x ^ p1'` gives the next characters of the other plaintext based on your guess, and if it makes sense, then your guess was correct.

The key is determined from: `k = c2 ^ p2'`.

### Implementation
This is implemented in the following function, where the crib is a term for the guess:
```py
def crib_check(msg, idx, key, crib):
    chunks = [msg[i:i+32] for i in range(0, len(msg) - 32, 32)]

    a = chunks[idx]
    b = chunks[(idx + 255) % len(chunks)]
    iv = (idx + 1) % 256
    curr_key = key + iv
    a_e = int(a, 16) ^ curr_key
    b_e = int(b, 16) ^ curr_key
    print(a_e.to_bytes(16))
    print(b_e.to_bytes(16))

    x = a_e ^ b_e
    crib_e = int.from_bytes(crib.encode()) << (16 * 8 - len(crib) * 8)
    output = x ^ crib_e
    print(output.to_bytes(16))
    new_key = output ^ b_e
    return (new_key, 16* 8 - len(crib) * 8)
```

We can then just guess and check the correct words.\
The shift is to only keep the new information about the key, since the bits outside of the range of your guess will be garbage.
```py
key = 0
(gained_key, crib_len) = crib_check(msg, 0, key, 'Chapter 1 ')
key += gained_key >> crib_len << crib_len

# decrypt(msg, key) in between to find a new chunk
(gained_key, crib_len) = crib_check(msg, 294, key, 'of information ') 
key += gained_key >> crib_len << crib_len

# decrypt(msg, key) in between to find a new chunk
(gained_key, crib_len) = crib_check(msg, 361, key, ' the friendships')
key += gained_key >> crib_len << crib_len
```
The final text is given by:
```py
dec = decrypt(msg, key - 1)
print(dec.decode('utf-8'))
```
I'm not really sure why the -1 is necessary, but I think it has to do with the IV starting at 1.
I was able to determine that it was needed by just bruteforcing the last byte of the key.

### Flag
Finally, with the full text, we can just run `python3 bitbybit.py | grep pctf` and we'll have the flag.

```
In a dimly lit room in downtown Chicago, Ethan "Cipher" Reynolds sat hunched over his computer, the glow from the monitor casting a bluish hue across his determined face. Th
e clock on the wall ticked past midnight, but Ethan paid no mind. He was deep into cracking one of the most intricate encryption systems hed ever encountered a challenge pos
ted on an obscure forum known for its cryptographic puzzles. The flag hidden within, pctf{4_th3_tw0_t1m3_4a324510356}
```
Flag: `pctf{4_th3_tw0_t1m3_4a324510356}`

Full solution file: [`bitbybit.py`](/writeups/bitbybit/bitbybit.py)





