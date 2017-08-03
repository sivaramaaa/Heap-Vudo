# HITCON CTF 2014 - Stkof 

The given binary had a global-pointer and a heap overflow

 * we unlink the fake chunk 
 * overwrite atoll got with pop ; pop ; pop ; ret
 * causing esp to point to our buffer 
 * now we pivot stack to global pointer by using pop rsp ; ret
 * now execute the ropchain stored in one of the chunk 
 * and with this we can leak addr
 * after computing system addr we srore that addr in an area and finally return to it   


#### \# Unlink &nbsp; \# stack-pivot &nbsp; \# ROP