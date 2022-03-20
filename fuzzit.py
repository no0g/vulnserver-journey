#!/bin/python
import argparse
# resolve argv parsing problem
import pwnlib.args
pwnlib.args.free_form = False
from pwn import *

# init parser
parser = argparse.ArgumentParser(description=
"""Fuzzing easier
example: python fuzzit.py -H 192.168.230.128 -P 9999 -p KSTAN
{sending b"KSTAN (payload)"}
""")
# Remote Host
parser.add_argument('-H','--host',dest='host', help="Set remote target")
# Host Port
parser.add_argument('-P','--port',dest='port', help="Set remote target port")
# Prepend an Option
parser.add_argument('-p','--prepend',dest='prepend', help="Set value custom value required before fuzzing payload")
# Range of payload length e.g 100,200
parser.add_argument('-r','--range',dest='range', default="100-1000", help="Set range of payload length e.g(e.g 100-1000)")
# Increment value
parser.add_argument('-i','--increment',dest='increment', default=100, help="Set increment value (default=100)")


args = parser.parse_args()

# set range
configuredRange=args.range
[botval,upperval]=args.range.split('-')
botval=int(botval);upperval=int(upperval);
# set increment
increment=int(args.increment) if args.increment else exit(0)
# set host
host=args.host if args.host  else exit(0)
# set port
port=int(args.port) if args.port else exit(0)
# set prepend value if needed
prepend=args.prepend
prependIsSet=True if prepend else False



print("[+] Configured Range: Bottom={}, Upper={}".format(botval,upperval))
print("[+] Configured Incremental Val: {}".format(increment))
print('[+] Configured Target: {}:{}'.format(host,port))
print("[+] Configured custom prepend value: {}".format(prepend)) if prependIsSet else print("[-] No custom prepend value set") 

con = remote(host,port)
try:
    print("Welcome Msg: " + con.recvline().decode())
except:
    print('no welcome msg')
while(botval<upperval):
    try:
        print('[0] Sending {} bytes'.format(botval))
        con.sendline((prepend+" ").encode() + cyclic(int(botval))) if prependIsSet else con.sendline(cyclic(int(botval)))
        print((prepend+" ").encode() + cyclic(botval)) if prependIsSet else print(cyclic(botval))
        print("[1] Output: {}".format(con.recvline().decode()))
    except:
        print(Exception())
        print('system not responding')
        break
    botval+=increment

