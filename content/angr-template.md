Title: Getting acquainted with angr
Date: 2020-03-09
Slug: angr-tips-and-tricks

[TOC]

## Introduction 

This post aimes to be the first in a series where I document my journey in learning [angr](https://github.com/angr/angr) to solve real-world problems. At first, CTF challenges will be used as examples, the goal being to learn to handle more and more corner cases as I am making progress.

Learning to use [angr](https://github.com/angr/angr) effectively was a personal objective I had in mind for the past year. Unfortunately, the examples I found online were either too old, too simple or too complicated. In view of that, an emphasis will be put on explaining solutions to every problem encountered or potential gotchas.

Here are the things I would like to eventually be able to do with [angr](https://github.com/angr/angr):

* Assist me in my day-to-day reverse-engineering tasks.
* Binary deobfuscation.
* Automate most of the job when a binary embbeds a Virtual Machine to protect some algorithm.
* Solve hard CTF tasks where the 10 line [angr](https://github.com/angr/angr) template does not suffice ;-)

So, by the end of it, expect to dig very deep in [angr](https://github.com/angr/angr)'s internals, so that it stops being a black-box that either solves a challenge or gets stuck who knows where.

## About this post's content

The takeaways for this post are the following:

* A good and simple [angr](https://github.com/angr/angr) template to solve a basic challenge, with debug tricks to understand what [angr](https://github.com/angr/angr) is doing.
* Helping [angr](https://github.com/angr/angr) to go faster.
* Interfacing with memory to put constraints on specific variables within a binary.
* Hook functions to summarize their behaviour. Reverse-engineering will never be fully automated, instead it is better to focus on a trade-off where we manually perform some easy tasks and let [angr](https://github.com/angr/angr) do the thinking stuff :-)

## Test binary

To practice with [angr](https://github.com/angr/angr), the following simple C program will be used:

```C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_error(char* param_1, int param_2)

{
  char *pcVar1;
  
  if (param_2 != 0) {
    pcVar1 = strerror(param_2);
    fprintf(stderr,"%s : \"%s\"\n",param_1,pcVar1);
  }
  return;
}

void *get_user_input(void *param_1)
{
    int *piVar1;
    size_t input_size;
    int iVar2;
    int index;

    index = 0;
    char* user_input = param_1;
    user_input = (char*)malloc(2);

    if (param_1 == 0x0) {
        display_error("Allocating memory",0);
    }

    while (1)   {

        iVar2 = getchar();
        user_input[index] = (char)iVar2;

        if (user_input[index] == '\n')  {
            break;
        }

        input_size = index + 2;
        index = index + 1;
        user_input = realloc(user_input, input_size);

        if (user_input == 0x0)  {
            display_error("Reallocating memory", 0);
        }
    }

    user_input[index] = 0;
    return user_input;
}

int main(int argc, char **argv) {

    int iVar1;
    char *input_address;

    printf("Enter secret password: ");
    input_address = (char *) get_user_input(input_address);
    int result = strcmp(input_address, "123456789");

    if (result == 0)    {
        printf("Good, the password was : %s!\n", input_address);
    }   else    {
        puts("Try harder.");
    }

    return 0;
}

```

It is actually taken from a CTF task whose name I cannot cite, since it is still running. In any case, it will do for this post's purpose. In short, this program asks the user to input a secret password, compares it with "123456789" and outputs a message accordingly ("Good" or "Try harder").

In addition, the logic to fetch user input is intentionaly over-complicated to show a situation where [angr](https://github.com/angr/angr) will get stuck analyzing something useless.

Let's punch that code into a "test.c" file and then build it:

```bash

gcc test.c -o test.bin -m32 -no-pie
```

* -m32: compile for Intel 32-bit's architecture, so as to simplify the task.
* -no-pie: do not produce a Position Independant Executable, since it would add complexity to locate the addresses of the good/bad basic blocks.

Test the program:

```bash

$ ./test.bin
Enter secret password: 1234
Try harder.
$ ./test.bin
Enter secret password: 123456789
Good, the password was : 123456789!
```

## Reverse-engineering

Let's open the binary in your favorite disassembler (here, Binary Ninja is used but any other will do just as fine). The goal is retrieve the addresses of the following basic blocks:

* The basic block we would like to reach (0x8049353).
* The basic block we need to avoid (0x8049371).

[![Retrieve some useful addresses in Binary Ninja](/images/angr_01_addresses.png){:width=300px}](/images/angr_01_addresses.png "Retrieve some useful addresses in Binary Ninja"){class="mybox"}

In addition, I find it is more comfortable to choose an address in the "Good" basic block that is located after the `printf` instruction. Indeed, doing so allows to read `stdout` and check that the message "Good, the password was..." is indeed present.

Here is the disassembly for that basic block:

```asm
08049350  83ec08             sub     esp, 0x8
08049353  ff75f0             push    dword [ebp-0x10 {var_18_1}] {var_2c_1}
08049356  8d835be0ffff       lea     eax, [ebx-0x1fa5]  {data_804a05b, "Good, the password was : %s!\n"}
0804935c  50                 push    eax  {data_804a05b, "Good, the password was : %s!\n"}
0804935d  e8eefcffff         call    printf
08049362  83c410             add     esp, 0x10
08049365  eb12               jmp     0x8049379
```

We will use the address `0x8049362` as the `find` target.

## [angr](https://github.com/angr/angr) 101

Since the binary is very simple, we could solve the challenge with the most basic [angr](https://github.com/angr/angr) template that is often displayed as example when introducing the framework:

```python
import angr
import sys
import claripy

simgr = None
proj = None
state = None

ADDRESS_TO_REACH = 0x8049362
ADDRESS_TO_AVOID = 0x8049371
FLAG_SIZE = 9

def main():
    global simgr
    global proj
    global state

    proj = angr.Project("test.bin", load_options={'auto_load_libs': False})
    flag = claripy.BVS('flag', FLAG_SIZE*8)
    state = proj.factory.blank_state(stdin=flag)
    simgr = proj.factory.simulation_manager(state)

    simgr.explore(
        find=(ADDRESS_TO_REACH),
        avoid=(ADDRESS_TO_AVOID),
        num_find=1
    )

    if len(simgr.found) > 0:
        
        found = simgr.found[0]
        output = found.posix.dumps(sys.stdout.fileno())

        if b"Good" in output:
            print("WIN:" +  output.decode('utf-8', errors='ignore'))
            input_data = found.posix.stdin.load(0, found.posix.stdin.size)
            print(f"The flag is: \"{state.solver.eval(input_data, cast_to=bytes)}\"")
        else:
            print("Wut")

    print("Done")

if __name__ == '__main__':
    main()
```

That small snippet of code is adapted from the [official documentation](https://docs.angr.io/core-concepts/pathgroups). Maybe worth noting is the way user input is retrieved once a path was found to the specified basic block:


```python
input_data = found.posix.stdin.load(0, found.posix.stdin.size)
print(f"The flag is: \"{state.solver.eval(input_data, cast_to=bytes)}\"")
```

To read stdin, and thus recover the input found by [angr](https://github.com/angr/angr), we must ask the solver to concretize stdin, which is accomplished with the function `eval` of the `solver` instance stored in the `found` state.

To access the other standard file descriptors, `dumps` can be useful:

```python
found.posix.dumps(fileno)
```

This allows to read contents from stdin, stdout or stderr, but the file descriptor must be specified as a parameter (for instance `sys.stdout.fileno()`)

## When [angr](https://github.com/angr/angr) is taking forever

Running the aforementionned script does not produce any result and [angr](https://github.com/angr/angr) seems to be stuck somewhere. To figure out the issue, it can be useful to enrich our template a bit. The goal is to be able to interrupt the script, drop into a Python interpreter and get some contextual info. To do that, let's add some code at the top of the script:

```python
import logging
import os

logging.getLogger('angr.manager').setLevel(logging.DEBUG)

import signal
def killmyself():
    os.system('kill %d' % os.getpid())

def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')

    cs = simgr.active[0].callstack
    print(cs)

    cfg = proj.analyses.CFGFast()

    print(f"Currently exploring function @ {hex(cs.current_function_address)}")
    get_fn_by_addr(cs.current_function_address)

    block = proj.factory.block(cs.call_site_addr)
    block.capstone.pp()

    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

def get_fn_by_addr(addr):
    fns = list(proj.kb.functions.items())

    for fn in fns:

        if addr == fn[0]: # fn is a tuple(addr, Function object)
            print(fn)
            break
```

Re-run the script and issue CTRL+C after a few seconds. You should get the following output:
```bash
WARNING | 2020-03-09 14:15:21,093 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0002a7e with 1 unconstrained bytes referenced from 0x90000a4 (realloc+0x0 in extern-address space (0xa4))
^CStopping Execution for Debug. If you want to kill the programm issue: killmyself()
Backtrace:
Frame 0: 0x804931e => 0x8049234, sp = 0x7ffeff8c
Frame 1: 0x9000104 => 0x80492f2, sp = 0x7ffeffcc
Frame 2: 0x80490e4 => 0x80490b0, sp = 0x7ffeffdc
Frame 3: 0x0 => 0x0, sp = 0xffffffff
Currently exploring function @ 0x8049234
(134517300, <Function get_user_input (134517300)>)
0x804931e:	add	esp, 0x10
0x8049321:	sub	esp, 0xc
0x8049324:	push	dword ptr [ebp - 0x10]
0x8049327:	call	0x8049234
Python 3.7.6 (default, Dec 30 2019, 19:38:26)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.13.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]:
```

As shown above, we now know that [angr](https://github.com/angr/angr) was exploring the function `get_user_input`. To get to that result, we had to:

1. Install an interrupt handler to catch CTRL+C.
2. Print the callstack using `simgr.active[0].callstack`
3. Run [angr](https://github.com/angr/angr)'s Control Flow Graph analysis to populate the `functions` in `kb` with `proj.analyses.CFGFast()`.
4. Correlate function addresses to symbols in the binary.

For that last step, this is done as follows:

```python

def get_fn_by_addr(addr):
    fns = list(proj.kb.functions.items())

    for fn in fns:

        if addr == fn[0]: # fn is a tuple(addr, Function object)
            print(fn)
            break

get_fn_by_addr(cs.current_function_address)
```

## Optimizing

I have yet to find a way to get an estimate of the time [angr](https://github.com/angr/angr) will take in a given function. However, it is not interesting to let [angr](https://github.com/angr/angr) analyze the function `get_user_input`, since basically it just gets some data from stdin, allocates memory to store it and returns the address of the buffer containing the user input.

In fact, we could abstract it all away and let [angr](https://github.com/angr/angr) reason about the real interesting things, which is finding the path to the "Good" basic block.

To do that, it is possible to setup a hook for a given address and symbol:

```python
proj.hook_symbol('get_user_input', GetString())
```

Then, the hook's handler is defined as follows:

```
class GetString(angr.SimProcedure):

    def run(self, argv):
        print(f'Called get_user_input with param {argv}')
        return RANDOM_MEMORY_ADDRESS
```

What this hook does is fixing the return value of `get_user_input` to `RANDOM_MEMORY_ADDRESS`, which can be any free address really.

Then, it is important to tell [angr](https://github.com/angr/angr) that this address is an array with constrained, symbolic values:

```python
my_buf = RANDOM_MEMORY_ADDRESS

for i, c in enumerate(flag.chop(8)):
    state.solver.add(char(state, c))
    state.memory.store(addr=my_buf+i, data=c)
```

Afterwards, it is also necessary to adapt the way the solution is retrieved:

```
-input_data = found.posix.stdin.load(0, found.posix.stdin.size)
-print(f"The flag is: \"{found.solver.eval(input_data, cast_to=bytes)}\"")

+solution = found.solver.eval(found.memory.load(RANDOM_MEMORY_ADDRESS, FLAG_SIZE), cast_to=bytes).rstrip(b'\0').decode('ascii', errors='ignore')
+print(f"The flag is: \"{solution}\"")
```

Also, we no longer instantiate a state with a symbolic stdin:

```
-state = proj.factory.blank_state(stdin=flag)
+state = proj.factory.blank_state()
```

## Final solution

Here is the final script:

```
import angr
import sys
import logging
import os
import struct
import claripy

logging.getLogger('angr.manager').setLevel(logging.DEBUG)
import signal

simgr = None
proj = None
state = None

RANDOM_MEMORY_ADDRESS = 0x99000000 # address chosen at random to store things in memory.
FLAG_SIZE = 9
ADDRESS_TO_REACH = 0x8049362
ADDRESS_TO_AVOID = 0x8049371

def killmyself():
    os.system('kill %d' % os.getpid())

def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')

    cs = simgr.active[0].callstack
    print(cs)

    cfg = proj.analyses.CFGFast()

    print(f"Currently exploring function @ {hex(cs.current_function_address)}")
    get_fn_by_addr(cs.current_function_address)

    block = proj.factory.block(cs.call_site_addr)
    block.capstone.pp()

    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

def get_fn_by_addr(addr):
    fns = list(proj.kb.functions.items())

    for fn in fns:

        if addr == fn[0]: # fn is a tuple(addr, Function object)
            print(fn)
            break

def char(state, c):
    # only printable chars
    return state.solver.And(c <= '~', c >= '\n')

class GetString(angr.SimProcedure):

    def run(self, argv):
        print(f'Called getString with param {argv}')
        return RANDOM_MEMORY_ADDRESS

def main():
    global simgr
    global proj
    global state

    proj = angr.Project("test.bin", load_options={'auto_load_libs': False})
    flag = claripy.BVS('flag', FLAG_SIZE*8)
    state = proj.factory.blank_state()

    my_buf = RANDOM_MEMORY_ADDRESS

    for i, c in enumerate(flag.chop(8)):
        state.solver.add(char(state, c))
        state.memory.store(addr=my_buf+i, data=c)

    proj.hook_symbol('get_user_input', GetString())

    simgr = proj.factory.simulation_manager(state)

    simgr.explore(
        find=(ADDRESS_TO_REACH),
        avoid=(ADDRESS_TO_AVOID),
        num_find=1
    )

    if len(simgr.found) > 0:
        
        found = simgr.found[0]
        output = found.posix.dumps(sys.stdout.fileno())

        if b"Good" in output:
            print("WIN:" +  output.decode('utf-8', errors='ignore'))
            solution = found.solver.eval(found.memory.load(RANDOM_MEMORY_ADDRESS, FLAG_SIZE), cast_to=bytes).rstrip(b'\0').decode('ascii', errors='ignore')
            print(f"The flag is: \"{solution}\"")
        else:
            print("Wut")
            print(output)

    print("Done")

if __name__ == '__main__':
    main()

```

Running this script takes around 3 seconds and produces the following output:

```bash
(angr) ➜  angr time python3 test_solve.py
WARNING | 2020-03-09 15:26:41,818 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,819 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,821 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,821 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,822 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,822 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,823 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,823 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,824 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,824 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,824 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,825 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,825 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,826 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,827 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,827 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,828 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:41,828 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
WARNING | 2020-03-09 15:26:42,145 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-03-09 15:26:42,145 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-03-09 15:26:42,145 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-03-09 15:26:42,145 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-03-09 15:26:42,146 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-03-09 15:26:42,146 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80493a0 (__libc_csu_init+0x10 in test.bin (0x80493a0))
Called getString with param <BV32 0x7ffeffb8>
WARNING | 2020-03-09 15:26:42,296 | angr.state_plugins.symbolic_memory | Filling memory at 0x99000009 with 247 unconstrained bytes referenced from 0x9000098 (strcmp+0x0 in extern-address space (0x98))
WIN:Enter secret password: Good, the password was : 12345678  @@   !

The flag is: "123456789"
Done
python3 test_solve.py  2.44s user 0.15s system 99% cpu 2.601 total
(angr) ➜  angr
```

## Conclusion

Of course, solving that task by hand would have been way faster. The goal was to learn to use [angr](https://github.com/angr/angr) to solve a specific part in the challenge and enable the tool to take a shortcut by providing it with a hindsight we got through reverse-engineering.

Interestingly, the test binary can be compiled for another architecture and the same [angr](https://github.com/angr/angr) script can be used to solve it, which demonstrates the power of such mature frameworks.

In the next posts, we will further explor [angr](https://github.com/angr/angr)'s capabilities with another, harder CTF challenge.