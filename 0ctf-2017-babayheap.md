# 0ctf Quals 2017 - Babyheap 

### Double allocation && Heap-overflow 

The binary given was NX , Pie , Stack canary enabled .

#### Reversing

It's functionalities are : 

* Allocate a chunk :  calloc(size,1)
    * Create a table in a mapped region 
    * table[0] = 1 ( to mark it as allocated )
    * table[1] = size 
    * table[2] = buff_addr 
    
* Fill data  : read( table[index]->buff, size_user )
  It causes heap overflow

* Free : free(buff), clear table[0,1,2]
  Hence no UAF possible

* Dump :  write ( table[index]->buff , table[index]->size ) 
  Hence cannot leak any value                    
                                          

#### Exploit 

##### Leak using Double allocation
  
```
0:  alloc(48)
1:  alloc(48) <-- fastbins 
2:  alloc(48)
3:  alloc(48)
4:  alloc(120)  <-- small bin
```

   
   * free 2,1 fast bin and overflow 1'st bin fd pointer using 0'th bin
   
   * now overwrite fd LSB bit with small bin addr LSB  <----- very clever move 
   
   * now if u alloc(48) u will get small bin  , but ...
   
   * to bypass the check done by malloc() after  retriving chunk , u have to overflow small bin 
      chnunk's size with 0x48 
      
   * now if u delete a chunk using index 4 , u can still dump small bin's fd using index 1  <---- double alloc
                                                                                                  libc leak           
              
##### Hijacking control flow 

* Now we have only libc leak , where to write fd pointer with ???
 i found in one writeup there is function pointer called __malloc_hook whose function 
 gets executed by malloc if it's not null 
 
* Now what to write in function ponter  ????
 An easy solution that comes handy in this situation is one_gadget :)  


                                                                                                                          
                                                                                                   