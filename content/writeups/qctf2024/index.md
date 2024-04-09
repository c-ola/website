---
title: "QCTF 2024"
date: 2024-04-08
draft: false
description: "Series of writeups for QCTF2024"
tags: ["example", "tag"]
---

## Echo Me
After connecting to the given server with ssh, we are met with a program that prints back anything that you send.
![Example of the Echo Me program](/writeups/qctf2024/echome_show.png)
Since all the program does is read lines, and print them back out, all you can really do is use format specifiers to find an exploit.
To start, I just sent a bunch of `%x`s.
![First attempt](/writeups/qctf2024/echome_findpattern.png)
We can see that there is a repeating 8 `%x` long pattern. Converting this to hex results in some recognizeable text, but half of it is garbage.
![Wrong numbers](/writeups/qctf2024/echome_wrongorder.png)
This means we are likely missing some info, so we can use `%lx` to print out long ints. We then get: 
![Correct numbers](/writeups/qctf2024/echome_correct_output.png)
Copying the numbers `fbad2288.7ffd71a15c60.0.0.74737b2d46544351.733068742d6b6334.66746e3172702d33.7d73` into cyberchef, we get alot more readable characters, but there is still some garbage, so we start removing from the front (this is because the endianess is swapped).
We can then get our flag.
![Final Answer](/writeups/qctf2024/echome_final.png)
This gives us the flag `QCTF-{st4ck-th0s3-pr1ntfs}` which is correct!

