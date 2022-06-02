import subprocess
import sys


class Color:
   PURPLE = '\033[1;35;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   END = '\033[1;37;0m'
   CYAN = '\033[1;36;48m'


class Malware:

    def __init__(self, domain_name, client_ip, account_clean=False, wp_up_to_date=False, account_limited=True,
                 username=None, host=None):
        self.domain = domain_name
        self.ip = client_ip
        self.account_clean = account_clean
        self.wp_up_to_date = wp_up_to_date
        self.account_limited = account_limited
        self.username = username
        self.host = host

    def obtain_host(self):
        # URL = f"http://{self.domain}/.well-known/sg-hosted-ping" ### OLD METHOD
        # page = requests.get(URL)
        # obtain_host = []
        # obtain_host.append(page.text)
        # hostname = obtain_host[0].split()
        # self.host = hostname[1]
        command = f"curl -s http://{self.domain}/.well-known/sg-hosted-ping | awk '{{print $2}}'"
        self.host = subprocess.check_output(command, shell=True, text=True)
        if 'sgvps.net' not in self.host and 'siteground' not in self.host:
            self.host = input(f"\n{Color.PURPLE}Can't detect the hostname automatically, please type it here: {Color.END}")
        else:
            self.host = self.host.strip()

    def obtain_username(self):
        try:
            user = f"asl {self.domain} | grep -Eo '[u][0-9]+[-][a-z0-9]+'"
            self.username = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), user],
                                                            text=True)
            self.username = self.username.strip()
        except subprocess.CalledProcessError:
            sys.exit('\nPLEASE GENERATE SSH KEY AND TRY AGAIN!\n')

    def malware_check(self):
        try:
            malscan_output = []
            command = f" malscan scan {self.username} ."
            ssh = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command], text=True)
            result = ssh
            malscan_output.append(result)
            seprate_output = malscan_output[0].split("\n")
            if len(seprate_output) >= 9:
                return print(result)
            else:
                self.account_clean = True
                return print(result)
        except subprocess.CalledProcessError:
            sys.exit('\nPLEASE GENERATE SSH KEY AND TRY AGAIN!\n')

    def wordpress(self):
        wp_themes = "All plugins are up to date!"
        wp_plugins = "All themes are up to date!"
        updated_check = []
        command = 'bash -c "$(curl -s https://galinvelikov.com/wp_plug_theme.sh)"'
        wp_updates = subprocess.check_output(["ssh", "-p18765", "{}@{}".format(self.username, self.host), command],
                                             text=True)
        outdates = wp_updates
        updated_check.append(outdates)
        list_ouput = updated_check[0].split("\n")
        if wp_themes in list_ouput and wp_plugins in list_ouput:
            self.wp_up_to_date = True
        return print(outdates)

    def allow_ip(self):
        old_ip = []
        final_ips = []
        awk = "awk '{print $3}'"
        command = f"sc site features_all {self.username} | grep 'suspended_web' | {awk}"
        ip_check = f"sc site features_all {self.username} | grep 'suspended_web_allow' | {awk}"
        whitelist = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command])
        ip_check_command = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), ip_check])
        whitelist_result = bytes.decode(whitelist)
        new_ip = bytes.decode(ip_check_command)
        old_ip.append(new_ip)
        for new_line in old_ip:
            if "\n" in new_line:
                final_ips.append(new_line.replace("\n", ""))
            else:
                final_ips.append(new_line)
        separate_ips = [word for line in final_ips for word in line.split(',')]
        if whitelist_result[0] == '-' or whitelist_result[0] == '0':
            self.account_limited = False
            return print(f"{Color.CYAN}The account is not limited!{Color.END}")
        elif int(whitelist_result[0]) == 1:
            if self.ip not in separate_ips:
                if "-" not in final_ips:
                    print(f"{Color.RED}Multiple IP allow\n")
                    final_ips.append(self.ip)
                    final_list_ip = ','.join(final_ips)
                    ip_allow = f"sc site features_set {self.username} suspended_web_allow={final_list_ip}"
                    ssh = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), ip_allow],
                                                  text=True)
                    result = ssh
                    print(f"The IP addresses {final_list_ip} have been successfully allowed")
                    return print(f'{result}{Color.END}')
                else:
                    print(f'{Color.RED}Single IP Allow\n')
                    single_ip_allow = f"sc site features_set {self.username} suspended_web_allow={self.ip}"
                    ssh = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host),
                                                   single_ip_allow], text=True)
                    result = ssh
                    print(f"The IP address {self.ip} has been successfully allowed")
                    return print(f'{result}{Color.END}')
            else:
                print(f"{Color.RED}The IP Address {self.ip} is already allowed!{Color.END}")

    def limits_remove(self):

        if self.account_clean and self.wp_up_to_date and self.account_limited:
            print("The hosting account is clean and the website is up to date. Would you like to remove the limits?")
            yes = input("Yes or No\n")
            if yes.lower() == "yes":
                command = f"sc site features_set {self.username} suspended_web=0 suspended_web_allow"
                remove_limits = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host),
                                                         command], text=True)
                decoded = remove_limits
                print(f"\n{Color.CYAN}The limits have been lifted up")
                return print(f"\n{decoded}{Color.END}")
            else:
                print(f"{Color.CYAN}No further actions would be taken!{Color.END}")
        else:
            print(f"\n{Color.CYAN}The account needs to be cleaned or website updated!\n{Color.END}")

    def incorrect_permissions(self):

        try:
            command = "find ~/www/ ! -perm -u=r ! -perm -u=w ! -perm -u=x"
            fix_command = "find ~/www/ -type f ! -perm -200 ! -perm -100 | xargs chmod 644"
            perm_fix = subprocess.check_output(["ssh", "-p18765", "{}@{}".format(self.username, self.host),
                                                command], text=True)

            if len(perm_fix) > 0:
                print(f"\n{Color.RED}!!!Found files with incorrect permissions!!!{Color.END}\n{perm_fix}")
                print("Would you like to fix the incorrect file permissions with default ones (644)?\n")
                yes = input("Yes/No\n")
                if yes.lower():
                    perm_fix = subprocess.check_output(["ssh", "-p18765", "{}@{}".format(self.username, self.host),
                                                        fix_command], text=True)
                    print(f"\n{Color.CYAN}The permissions for the files have been fixed{Color.END}\n")
                else:
                    print(f"{Color.CYAN}As commanded, no further actions are taken{Color.END}")
            else:
                print(f"\n{Color.CYAN}Job well done! All files are with correct permissions!{Color.END}\n")
        except subprocess.CalledProcessError:
            sys.exit('\nPLEASE GENERATE SSH KEY AND TRY AGAIN!\n')

    def email_limits(self):
        awk = "awk '{print $3}'"
        email_limit_check = f"sc site features_all {self.username} | grep 'suspended_email' | {awk}"
        email_check = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host),
                                               email_limit_check], text=True)
        remove_limits_command = f"sc site features_set {self.username} suspended_email=0 " \
                                f"suspended_email_script_sending=0"
        if '1' in email_check:
            print(f"{Color.RED}\nEmail Limits have been found, would like to remove them?{Color.END}")
            yes = input("Yes or No\n")
            if yes.lower() == "yes":
                remove_limit = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host),
                                                       remove_limits_command], text=True)
                print(f"{Color.RED}\nThe email limits have been removed!{Color.END}")
                print(f"\n{remove_limit}")
            else:
                print(f"{Color.RED}\nAs commanded, no further actions would be taken! My Job here is done!{Color.END}")


domain = input("Please type the domain name: ")
ip = input("Please type client's IP address: ")

malware = Malware(domain, ip)
malware.obtain_host()
malware.obtain_username()
malware.incorrect_permissions()
malware.malware_check()
malware.wordpress()
malware.allow_ip()
malware.limits_remove()
malware.email_limits()