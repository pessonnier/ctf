from pwn import ELF, disasm

def t0():
    print(disasm(b'Oxfacade'))

def t2():
    libc = ELF('libc.so')
    system_off = libc.symbols['system']
    sh_off = next(libc.search(b'sh\x00'))
    binsh_off = next(libc.search(b'/bin/sh\x00'))
    print(system_off, sh_off, binsh_off)

def t3():
    import hashlib
    # détecté par https://crackstation.net/
    print(hashlib.md5('bob'.encode('ascii')).hexdigest())
    print(hashlib.md5('Bob'.encode('ascii')).hexdigest())
    print(hashlib.md5('bob3'.encode('ascii')).hexdigest())
    print(hashlib.md5('bob314'.encode('ascii')).hexdigest())
    print(hashlib.md5('Bob314'.encode('ascii')).hexdigest()) # X
    print(hashlib.md5('calamar'.encode('ascii')).hexdigest())
    print(hashlib.md5('Calamar'.encode('ascii')).hexdigest())
    print(hashlib.md5('calamaR'.encode('ascii')).hexdigest())
    print(hashlib.md5('cAlAmAr'.encode('ascii')).hexdigest())
    print(hashlib.md5('calamar314'.encode('ascii')).hexdigest()) # X

def t4():
    cat = ELF('./cat')
    print('asan :', cat.asan)
    print('aslr :', cat.aslr)
    print('build :', cat.build)
    print('stack canary :', cat.canary)
    print('elftype :', cat.elftype)
    print('endian :', cat.endian)
    print('built with Fortify Source -DFORTIFY :', cat.fortify)
    print('Memory Sanitizer :', cat.msan)
    print('NX protections :', cat.nx)
    print('os :', cat.os)
    print('packed with UPX :', cat.packed)
    print('position-independent :', cat.pie)
    print('RELRO protections :', cat.relro)
    print('rpath :', cat.rpath)
    print('runpath :', cat.runpath)
    print('statically linked :', cat.statically_linked)
    print('Undefined Behavior Sanitizer :', cat.ubsan)
    print('executable stack :', cat.execstack)

def t5():
    cat = ELF('./cat')
    print('### Global Offset Table')
    for nom, adr in cat.got.items():
        print (nom,':\t', hex(adr))
    print('### all Procedure Linkate Table')
    for nom, adr in cat.plt.items():
        print (nom,':\t', hex(adr))
    print('### functions ')
    for nom, x in cat.functions.items():
        print (nom,':\t', x)
    print('### all symbols in the ELF')
    for nom, x in cat.symbols.items():
        print (nom,':\t', hex(x))
    print('### library loaded')
    for nom, x in cat.libs.items():
        print (nom,':\t', hex(x))
    print('### every mapping')
    for nom, x in cat.maps.items():
        print (nom,':\t', hex(x))

t5()
