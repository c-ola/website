---
title: "QCTF 2024"
date: 2024-04-08
draft: false
description: "Series of writeups for QCTF 2024"
tags: ["ctf"]
showTableOfContents: true
---
These are my writeups for QCTF 2024, where I placed 4th in the competition, and 1st out of teams from Queen's University. (The chals are not up atm so I had to run some of the programs on my own machine)
## Echo Me
After connecting to the given server with SSH, we are met with a program that prints back anything that you send.
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

## Write Me
Connecting to the SSH server, we are met with a prompt to enter a justification and code for a launcof some sort (missile?). From the output, it is clear that we must somehow input the correct acitivation code (which is given to us after the program runs). Similarly to echome, this will be another format specifier exploit.
![Image of what writeme does](/writeups/qctf2024/writeme_1.png)
We first start off with entering `AAAA` followed by alot of `%x`s into the justification, since this is what ultimately gets printed back out to us. We also enter in some `A`s into the launch code to see if that gives anything.
![Writeme first attempt](/writeups/qctf2024/writeme_2.png)
We can see from this image that most of the values look like pointers (big numbers that only slightly change every attempt), but the 9th one stands out. If you also notice that the launch code is always somewhere between 0 and some number around 65000, you can surmise that it's stored in a 16-bit unsigned integer. This matches up perfectly with the 9th number of our output. After converting the hex number to decimal, we can confirm that they are the same.

If we can somehow change that on our own, we can solve the challenge. This is where the `%n` format specifiers comes into play. It can assign a variable the number of characters before it in the a print statement. Combining this with the knowledge that the number is in the 9th position of the output, we get the string `%8$n` as our exploit. This will make the launch code 0.
![Writeme success](/writeups/qctf2024/writeme_3.png)
With this we get the flag `QCTF-{l4unch3d-ar0und-th3-st4ck}`.









