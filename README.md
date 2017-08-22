# pwnlib
Some stuff for CTF.

## My feature


### Shellcode module

You can easily use some shellcode

```
include Shellcode
shellcode(:x86)
orw(:x64, '/the/path/you/wanna/read') # open-read-write(stdout)
reverse_shell(:x86, '127.0.0.1', 25252)
```

### pack/unpack

Supported pack, unpack.(only little endian)

```
p32(0xdeadbeef)
p32(0xdeadbeef, 0xbeefdead)
u64("AAAAAAAA")
```

### Use constants

Some important constants was defined such as NULL, STDIN_FILENO, O\_RDONLY.

### Sasm

Sasm can easily assemble.

```
require 'sasm'

sasm = Sasm.new(:x86)
code = <<EOS
mov al,1
xor ebx, ebx
int 0x80
EOS
sasm.as(code)
```
