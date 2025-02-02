---
title: "rev/Typecheck UMDCTF 2024"
date: 2024-04-28
draft: false
description: "Write up for the Typecheck challenge from UMDCTF 2024"
tags: ["ctf", "rev"]
showTableOfContents: true
---

## Description
My C++ code won't type check. Can you fix that for me?\
Note: you will need to set `-ftemplate-depth=10000` when compiling.\
Files: [`templates.hpp`](/writeups/typecheck/templates.hpp) and [`main.cpp`](/writeups/typecheck/main.cpp)

## Understanding the problem
The main function is in `main.cpp` and looks something like this:
```c++
#include "templates.hpp"
//flag is 60 chars
using flag_t = int_list_t <'f', 'l', 'a', 'g', ...>
using prog_t = int_list_t <2, 0, 3, 2, ... 40701, 2, 0, 3, ...>
int main() {
    vm_t<nil_t, prog_t, flag_t> b;

    b = (nil_t)b;
}
```
By the looks of things, we'll be dealing with some template wizardy. We can confirm this by taking a look at `templates.hpp`, where we can see it happening.

Before doing anything else, we can first compile the program as per the description.\
`g++ main.cpp templates.cpp -o witchcraft -ftemplate-depth=10000`\
It gives an error when compiling (with something about templates), so I decided to then try and understand what the templates are actually doing.

In the main function, `nil_t` (an empty struct), `prog_t` (list of numbers) and `flag_t` (our guess for the flag) are all passed in to the template for the struct `vm_t`.
Let's first find out what `int_list_t` does, since it is used by `prog_t` and `flag_t`.
The struct uses `cons<T, U>` to create a linked list of integer values. For example `cons<V<2>, cons<V<0>, V<3>>>` is equivalent to `int_list_t<2, 0, 3>`.

The next important struct is `vm_t`, which turns out to act as a virtual machine that operates on a stack. The stack is the denoted by S, IT are the instructions, and In is external input.

There are 5 different operations that can be executed on the stack, each corresponding to a value on IT:
- Add (`A_t`, IT: 0): pop two elements, push their sum
- Mul (`M_t`, IT: 1): pop two elements, push their product
- Push IT (`P_t`, IT: 2): pop the head of IT, push it to the stack
- Push In (uses `g`, IT: 3): pop the head of In, push it to the stack
- Condition Pop (`M_t`, IT: 4): pop if the top is equal to the head of IT

Now that we know what kind of spell is being cast, we can:
 - realize that the operations that are performed have to result in a value equal to the value after the any condition check instructions
 - recreate the same spell, but in python

## Solution
Our python program will look something like this:
```py
IT = [2, 0, 3, 2, 2, 47, 1, 0, 3, 12, 2, 24, 1, 0, 3, 16, 2, 67, 1, 0, 3, 18, 2, 89, 1, 0, 3, 22, 2, 59, 1, 0, 3, 41, 2, 61, 1, 0, 3, 51, 2, 19, 1, 0, 3, 56, 2, 45, 1, 0, 4, 40701,]
In = ['U', 'M', 'D', 'C', 'T', 'F', '{', ..., '}']
stack = []
itidx = 0

while itidx < len(it):
    instr = it[itidx]
    if instr == 0:
        stack.append(stack.pop(-1) + stack.pop(-1))
    elif instr == 1:
        stack.append(stack.pop(-1) * stack.pop(-1))
    elif instr == 2:
        stack.append(it[itidx + 1])
        itidx += 1
    elif instr == 3:
        stack.append(ord(In[IT[itidx + 1]])
        itidx += 1
    elif instr == 4:
        if stack[-1] == IT[itidx + 1]:
            stack.pop(-1)
        itidx += 1
    itidx += 1
```
After running this, we can see that the program is just doing:\
`a0*b0 + a1*b1 + ... + an*bn = c` 60 times\
We also only know the b values of this equation, since the others come from the flag, which we are trying to find out. This means that we can solve this with a system of linear equations.

Since we do not know what values we need in `In`, we record the values into two matrixes.
```py
import numpy as np
res = np.zeros(shape=(1,60), dtype=np.int64) # what it should equal
b = np.zeros(shape=(60, 60), dtype=np.int64) # our b s
row = 0
aidx = 0
```
And we modify the pushes and conditional pop
```py
while ...:
    ...
    elif instr == 2:
        stack.append(IT[itidx + 1])
        b[row][aidx] += IT[itidx + 1]
        itidx += 1
    elif instr == 3:
        stack.append(ord(In[IT[itidx + 1]])
        aidx = IT[itidx + 1]
        itidx += 1
    elif instr == 4:
        if stack[-1] == IT[itidx + 1]:
            stack.pop(-1)
        res[0][row] = IT[itidx + 1]
        itidx += 1
        row += 1
```

And finally we solve for the matrix `a`.
```py
a = np.linalg.solve(b, res[0])
strres = ""
for i in range(60):
    strres += chr(int(np.rint(a[i])))
print(strres)
```

This gives us the flag:\
`UMDCTF{c++_templates_are_the_reason_for_the_butlerian_jihad}`\
Which is correct, meaning we have succesffully deciphered the template wizardry!

Full solution file: [`typecheck.py`](/writeups/typecheck/typecheck.py)





