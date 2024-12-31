# shrun

A simple shellcode runner for Windows/Linux.

## Features

- Set a Breakpoint before the shellcode entrypoint
- C/Python binding

## Build

```
> mkdir build
> cmake ..
> cmake --build .
```

## Usage

Executable:

```
Usage: ./shrun <shellcode file>

    Options:
    -b: Set a breakpoint before the shellcode entrypoint (x86/x64 only)
    -v: Verbose
    -h: Show help
```

Running the shellcode.

```
> ./shrun ../examples/nop.bin
```

`-b` option is useful for debugging.
There is no need to manually insert a breakpoint at the shellcode entrypoint.

```
> gdb -q -nx shrun
(gdb) r shellcode.bin -b
Starting program: /usr/bin/shrun ../shellcode.bin -b
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
shell code address=0x55555555b001

Program received signal SIGTRAP, Trace/breakpoint trap.
0x000055555555b001 in ?? ()
(gdb) x/5i $rip
=> 0x55555555b001:	nop
   0x55555555b002:	nop
   0x55555555b003:	nop
   0x55555555b004:	nop
   0x55555555b005:	nop
```

Python (Please build so/dll first!):

```python
from shrun import Shrun

with open('./examples/ret0x12345678.bin', 'rb') as f:
    shcode = f.read()
code = Shrun(shcode,path_to_lib='shrun.so')
ret = code.run()
print(f'Returned 0x{ret:016x}')
```

Pass arguments:

```python
from shrun import Shrun

with open('./examples/memcpy-x64-linux.bin', 'rb') as f:
    shcode = f.read()

code = Shrun(shcode, path_to_lib='shrun.so')
a1 = b"abcde"
a2 = b"xyz"
print(f'{a1=}')  # b'abcde'
ret = code.run_with_args(a1, a2, 3)
print(f'Returned 0x{ret:016x}')
print(f'{a1=}')  # b'xyzde'
```

## LICENSE

See ./LICENSE.
