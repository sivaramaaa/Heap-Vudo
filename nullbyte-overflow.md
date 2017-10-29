## Null Byte Overflow

For This method to work 

* U  just need to have single byte overflow over the size metadata of the chunk

#### Exploit steps 

1) malloc( overflowing_chunk )

2) malloc(0x220) # chunk that is going to be shrinked

3) Make sure u fill it with "A"*0x1f0+pack(0x200)+"B"x40 , so that it passes the 

``` prevsize (next_chunk) == size  ``` check
(NOTE :"A"*0x1f0 coz we are filling from (p+0x10))

4) malloc( 0x100 ) # the chunk going to be fooled C

5) free ( 2'nd chunk )

6)  Overflow the second chunk , now size = 0x200 , but 3'rd still thinks that it's size is 0x230 coz the prev size will not be updated 

7) malloc (0x100) # b1

8) malloc(x) # This the chunk u can overflow completely 

9) malloc(y) # the wall

10) free(b1)
11) free(c)

12) malloc(0x300) # voila magic chunk which allows us to overflow
