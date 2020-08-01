---
layout: post
title:  "Beginner's Guide to ROP (WIP)"
date:   2020-07-29 14:46:00 +0100
categories: pwn ropemporium
---
# Prior knowledgde
For this guide I will be using 64 bit ELF's. Learning the basics of 64 bit assembly code will be extremely useful during the reverse engineering process as well as when developing more complex rop chains. There are many great resources scattered around for this topic however a great reference guide, that I still use to this day, is [Assembly - Nightmare][nightmare-assembly]. It has many examples and explains the fundamental concepts in a very easy to grasp way. You don't need to learn all of this, just enough to be able to have a general idea of what each instruction does. Don't stress too much about this, you'll definitely learn and improve as you go, although with absolutely zero prior knowledge the rest of this guide will seem like complete and utter gibberish.

# Tools used in this guide.
 - checksec (to check exploit mitigations implemented within the binary)
 - ltrace (used to check the size of the buffer)
 - gdb (to debug the binary)
 - gef (a wrapper for gdb to provide some extended features)
 - [Ghidra][ghidra-download] (reverse engineering tool)
 - pwntools (a python library used to make writing binary exploit scripts much easier)
 - python (to write the exploit script)

# What is ROP?
**Return-oriented programming (ROP)** is an exploit technique that allows an attacker (us) to execute code despite there being exploit mitigations such as executable space protection. For this to be used, the attacker must first have control of the call stack which enabled them to attack **(https://en.wikipedia.org/wiki/Return-oriented_programming) continue later!**

# How the stack works

# The Binary
ret2win is the first and by far the easiest binary listed on [ROP Emporium][ropemporium] to exploit using rop. The binary itself is simple enough and this is what we have been told to do "*Locate a method within the binary that you want to call and do so by overwriting a saved return address on the stack*". Seems simple enough :)

# 

[ropemporium]:https://ropemporium.com/
[ret2win-home]: https://ropemporium.com/challenge/ret2win.html
[nightmare-assembly]: https://guyinatuxedo.github.io/01-intro_assembly/assembly/index.html
[ghidra-download]: https://ghidra-sre.org/
[ghidra-video]: https://www.youtube.com/watch?v=fTGTnrgjuGA