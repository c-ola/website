---
title: "Cassowary GB"
date: 2024-04-08
draft: false
description: "rust gameboy emulator"
tags: ["emulator", "gameboy"]
---

[github.com/c-ola/cassowary-gb](https://github.com/c-ola/cassowary-gb)

I started this project in the summer after having completed a computer architecture course at school.
That course was my favorite course of that semester and I wanted to further develop my understanding a similar topic.

To do that I decided to start working on an emulator.

I wanted to try something a little complex but hopefully not too difficult to write so I chose to emulate the original GameBoy.
I wanted to do this from scratch with only my own knowledge of how a cpu works so I started to do some research on the console.

The GameBoy uses a Sharp SM83, which is a slightly modified Z80 (two sets of prefix instructions are missing, and a couple others were replaced).
It is also a CISC instruction set so I had to figure out how that worked on my own because I had learnt RISC in my course.

My language of choice to code the project was Rust. I already had a strong understanding of C so I wanted to learn another fast low-level language.

Not completed...

