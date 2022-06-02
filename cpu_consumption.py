#Created by Galin Velikov
import subprocess
import json
import sys


class Color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'


class CpuAnalyzer:

    def __init__(self, domain, host=None, uid=None, cpu_m=None, cpu_d=None, cpu_exec=None, cpu_exec_m=None, shared=False, cloud=False):
        self.domain = domain
        self.host = host
        self.shared = shared
        self.cloud = cloud
        self.uid = uid
        self.cpu_m = cpu_m
        self.cpu_d = cpu_d
        self.cpu_exec = cpu_exec
        self.cpu_exec_m = cpu_exec_m

    def executions(self):
        if self.cloud:
            command = f"cat /usr/local/apache/logs/suexec_log | awk '{{print $7}}'| sort | uniq -c | sort -n | tail -n10"
            ssh_comm = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command], text=True)
            print(f"{Color.GREEN}==========Top 10 executed scripts==========\n{Color.END}")
            print(f"{ssh_comm}{Color.END}")
        else:
            command = f"cat /usr/local/apache/logs/suexec_log | grep '{self.domain}' | awk '{{print $7}}'| sort | uniq -c | sort -n | tail -n10"
            ssh_comm = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command], text=True)
            print(f"{Color.GREEN}==========Top 10 executed scripts==========\n{Color.END}")
            print(f"{ssh_comm}{Color.END}")

    def data_collection(self):
        command = f"sc site info {self.domain} -j -f uid"
        client_username = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command], text=True)
        self.uid = ''.join([i for i in client_username if i.isdigit()])

    def server_type(self):

        try:
            command = f"curl -s http://{self.domain}/.well-known/sg-hosted-ping | awk '{{print $2}}'"
            self.host = subprocess.check_output(command, shell=True, text=True)
            if 'sgvps.net' not in self.host and 'siteground' not in self.host:
                self.host = input(f"\n{Color.PURPLE}Can't detect the hostname automatically, please type it here: {Color.END}")
            else:
                self.host = self.host.strip()

            if "sgvps.net" in self.host:
                self.cloud = True
                print(f"\n{Color.RED}This is a Cloud container, starting to scan top 5 domains")
                print(f"\nThe hostname is {self.host}{Color.END}")
                cpu_analyzer.cloud_container()

            elif "siteground" in self.host:
                self.shared = True
                print(f"\n{Color.RED}This is a shared server, starting to scan the given domain {domain.upper()}")
                print(f"\nThe hostname is {self.host}{Color.END}")
                cpu_analyzer.data_collection()
                cpu_analyzer.cpu_data_shared()
                cpu_analyzer.cpu_by_cron()
        except subprocess.CalledProcessError:
            sys.exit('\nPLEASE GENERATE SSH KEY AND TRY AGAIN!\n')

    def cpu_data_shared(self):
        command = f"cat /var/cache/multistatsd.cache | jq '.[\"{self.uid}\"] | .http'"
        ssh = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), command])
        data_json = json.loads(ssh)
        print(f"\n==========CPU taken by http==========")
        for key, value in data_json.items():
            if key == 'cpu_time_monthly':  # CPU Time usage from the beginning of the month
                self.cpu_m = value
                print(f"\n{Color.RED}Monthly CPU seconds are {value:.2f}{Color.END}")
            elif key == 'cpu_time_daily':
                self.cpu_d = value
                print(f"\n{Color.RED}Daily CPU seconds are {value:.2f}{Color.END}")
            elif key == 'executions_daily':
                self.cpu_exec = value
                print(f"\n{Color.RED}Daily executions are {value}{Color.END}")
            elif key == 'executions':
                self.cpu_exec_m = value
                print(f"\n{Color.RED}Monthly executions are {value}{Color.END}")

    def cloud_container(self):
        domain_name = 'sc site list -j -f name,uid | jq "."'
        cpu_stats = 'cat /var/cache/multistatsd.cache | jq "."'
        ssh_cpu = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), cpu_stats])
        ssh_domain_name = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), domain_name])
        domain_json = json.loads(ssh_domain_name)  # uid domain name
        cpu_json = json.loads(ssh_cpu)
        cpu_http = {}
        cpu_cron = {}
        cpu_percent_cron = {}
        cpu_percent_http = {}
        final_percent = {}
        for userid, value in cpu_json.items():
            for domain in domain_json:
                if userid in str(domain['uid']):
                    if len(value['http']) > 2:
                        cpu_http[domain['name']] = value['http']['cpu_time_daily'], value['http']['executions_monthly'], \
                                                   value['http']['executions_daily'], value['http']['cpu_time_monthly']
                    if len(value['cron']) > 2:
                        cpu_cron[domain['name']] = value['cron']['cpu_time_daily'], value['cron']['executions_monthly'], \
                                                   value['cron']['executions_daily'], value['cron']['cpu_time_monthly']

        sorted_cpu_http = sorted(cpu_http.items(), key=lambda x: x[1][3], reverse=True)
        print(f"\n==========Top 5 websites sorted by CPU taken by http==========")
        for el in range(0, 5):
            if len(sorted_cpu_http) > el:
                cpu_percent_http[sorted_cpu_http[el][0]] = sorted_cpu_http[el][-1][-1]
                print(f"\n{Color.YELLOW}{sorted_cpu_http[el][0]}, {sorted_cpu_http[el][-1][-1]:.2f}{Color.END}")

        sorted_cpu_cron = sorted(cpu_cron.items(), key=lambda x: x[1][3], reverse=True)
        print("\n==========Top 5 websites sorted by % CPU taken by CronJobs==========")
        for el in range(0, 5):
            if el < len(sorted_cpu_cron):
                cpu_percent_cron[sorted_cpu_cron[el][0]] = sorted_cpu_cron[el][-1][-1]
        for dom, val in cpu_percent_http.items():
            for cron_key, value_cron in cpu_percent_cron.items():
                if dom == cron_key:
                    result = value_cron / (value_cron + val) * 100
                    final_percent[dom] = result
        if len(final_percent) > 0:
            for final_dom, final_value in sorted(final_percent.items(), key=lambda x: x[1], reverse=True):
                print(f"\n{Color.YELLOW}{final_dom} {final_value:.2f}%{Color.END}")
        else:
            print(f"\n{Color.YELLOW}No CronJobs found{Color.END}")

        sorted_cpu_http = sorted(cpu_http.items(), key=lambda x: x[1][1], reverse=True)
        print("\n==========Top 5 websites sorted by CPU taken by executions==========")
        for el in range(0, 5):
            if len(sorted_cpu_http) > el:
                print(f"\n{Color.YELLOW}{sorted_cpu_http[el][0]}, {sorted_cpu_http[el][-1][2]}{Color.END}")

    def cpu_by_cron(self):
        cron_command = f"cat /var/cache/multistatsd.cache | jq '.[\"{self.uid}\"] | .cron'"
        ssh_cron = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), cron_command])
        cron_data_json = json.loads(ssh_cron)
        print(f"\n{Color.YELLOW}==========CPU taken by CronJobs==========")
        if len(cron_data_json) > 1:
            for cron_key, value_cron in cron_data_json.items():
                if cron_key == 'cpu_time_monthly':
                    result = value_cron / (value_cron + self.cpu_m) * 100
                    print(f"\n{Color.YELLOW}Monthly % of CPU time taken by CronJobs is {result:.2f}%{Color.END}")
                elif cron_key == 'cpu_time_daily':
                    result = value_cron / (value_cron + self.cpu_d) * 100
                    print(f"\n{Color.YELLOW}Daily % of CPU time taken by CronJobs is {result:.2f}%{Color.END}")
                elif cron_key == 'executions_daily':
                    result = value_cron / (value_cron + self.cpu_exec) * 100
                    print(f"\n{Color.YELLOW}Daily % of executions made by CronJobs are {result:.2f}%{Color.END}")
                elif cron_key == 'executions':
                    result = value_cron / (value_cron + self.cpu_exec_m) * 100
                    print(f"\n{Color.YELLOW}Monthly % of executions made by CronJobs are {result:.2f}%{Color.END}")
        else:
            print(f"\n{Color.RED}No CronJobs Found\n{Color.END}")

    def top_ips(self):
        if self.cloud:
            ips_command = f"find /usr/local/apache/domlogs/ -maxdepth 1 -type f | xargs tail -n32456435678 |awk '{{print $1}}' |sort |uniq -c |sort -n |tail -10"
            ssh_command = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), ips_command], text=True)
            print(f"{Color.PURPLE}\n==========Top 10 access sorted By IPs==========\n")
            print(ssh_command)
            print(f"{Color.END}")
        else:
            ips_command = f"tail -n2323233432 /usr/local/apache/domlogs/{domain} |awk '{{print $1}}' |sort |uniq -c |sort -n |tail -10"
            ssh_command = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), ips_command], text=True)
            print(f"{Color.PURPLE}\n==========Top 10 access sorted By IPs==========\n")
            print(f"{ssh_command}{Color.END}")
            urls_command = f"tail -n23232332 /usr/local/apache/domlogs/{self.domain} | awk -F \" \" '{{print $7}}' | sort -n | uniq -c | sort -nr | head -n10"
            urls_output = subprocess.check_output(["ssh", "-p18765", "{}@{}".format("support", self.host), urls_command], text=True)
            print(f"{Color.CYAN}==========Top 10 visits sorted by URL==========\n")
            print(urls_output)
            print(f"{Color.END}")


domain = input("Please type the domain name: ")

cpu_analyzer = CpuAnalyzer(domain)
cpu_analyzer.server_type()
cpu_analyzer.data_collection()
cpu_analyzer.top_ips()
cpu_analyzer.executions()