---
title: "Mini SRC Assembler"
date: 2024-03-13
draft: false
categories: ["Projects"]
description: "customizable assembler"
tags: ["assembler"]
---

[Repo](https://github.com/c-ola/minisrc-assembler)

I first started this project because of an academic project where we were tasked with making a CPU in verilog. We got to a point where we had to start decoding instructions which meant we'd have to convert assembly instructions to their respective machine code.

This was a fairly cumbersome process (mapping everything by hand) so I decided to write a python script to automate this process.
Using my understanding of assembly that I learnt through my emulator as well as school, I was able to quickly write a script that could convert all the instructions that we were told to use in class, to machine code.

At the moment, it can hardly be called an assembler due to it's lack of features, however I do plan on adding a couple of things to it, and I might even go outside the scope of my school project for some things (interpreter??). 

Features that are currently supported are:
- converting files to hex
- converting single instructions to hex
- binary, signed/unsigned decimal, hex immediate value representations
- location tags (for branches, etc)
- directives (ORG)

Planned to support:
- exponential immediate values (e.g. 10e3)
- signed binary and hex
- macro immediate values
- initializing locations in memory to data (strings, integers, etc) (other directives)
- maybe maybe interpreter

