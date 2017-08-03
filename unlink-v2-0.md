# Unlink exploit 

For this method to work u need to have
 
* A global pointer 
* Heap overflow 

## Method to exploit :

### 1) Creation of fake chunk :
  
  * create a fake chunk inside a chunk pointed by global pointer
     with prev_size , size , fd , bk .
  
  * create fd and bk of fake chunk such that
   
       * &nbsp; \*(fd+12) = \*(bk+8) = \*(global ptr) = chunk_0 
       * &nbsp; With this we bypass the check P->fd->bk != P
  <br>
  *   Set size of fake chunk as :
       
       * &nbsp; chunk_0->size =  *fd  // prev_size            
       * &nbsp; this bypass the check made by libc chunksize(P) != fd->prev_size

### 2) Modifying chunk_1    

  * set  chunk1->prev_size = size_requested
  
       * such that it points at start of fake chunk 
       * this makes our chunk_0 to shrink
                           
  * set  chunk1->size prev inuse bit 0 
  
 ### 3) Unlink
 
  * Now free(chunk_1)
   
  * our fake chunk gets unlinked and causes to overwrite the global pointer 
  
  * We can now have arbitaray write
                                                                                                                                                                   