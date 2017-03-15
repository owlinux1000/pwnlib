require 'pwnlib'

p libc_offset("/lib/x86_64-linux-gnu/libc.so.6", "__libc_start_main")
