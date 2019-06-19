# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json, re
from lib.core.common import *
from subprocess import Popen, PIPE
from lib.core.ip.ip import *


# 作者：咚咚呛
# 分析进程信息
# 1、cpu使用超过70% 的进程
# 2、内存使用超过70% 的进程
# 3、隐藏的进程,主要针对mount --bind等挂接方式隐藏进程的检查,解决方案
# 4、是否存在反弹bash的进程
# 5、带有挖矿、黑客工具、可疑进程名的进程
# 6、当前执行的程序，判断可执行exe是否存在恶意域名特征特征

class Proc_Analysis:
    def __init__(self, cpu=70, mem=70):
        # cpu、内存使用率
        self.cpu, self.mem = cpu, mem
        # 可疑的进程列表
        self.process_backdoor = []
        self.name = u'Proc_Analysis'

    # 判断进程的可执行文件是否具备恶意特征
    def exe_analysis(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/proc/'): return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)): continue
                    malware = analysis_file(filepath)
                    if malware:
                        lnstr = os.readlink(filepath)
                        malice_result(self.name, u'exe process scan', lnstr, file, malware,
                                      u'[1]ls -a %s [2]strings %s' % (filepath, filepath), u'risk',
                                      programme=u'kill %s #kill malicious process' % lnstr)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤反弹shell特征
    def shell_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -efwww 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("grep -v 'grep'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p2.stdout, stdout=PIPE, shell=True)
            process = p3.stdout.read().splitlines()
            for pro in process:
                pro_info = pro.strip().split(' ', 3)
                if check_shell(pro_info[3]):
                    malice_result(self.name, u'reverse shell process scan', '', pro_info[1],
                                  u'process：%s' % pro_info[3].replace("\n", ""),
                                  u'[1]ps -efwww', u'risk', programme=u'kill %s #kill malicious process' % pro_info[1])
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤cpu和内存使用的可疑问题
    def work_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps aux 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen('grep -v PID', stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen('sort -rn -k3', stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen('head', stdin=p3.stdout, stdout=PIPE, shell=True)
            p5 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'", stdin=p4.stdout, stdout=PIPE, shell=True)
            p6 = Popen(
                "grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'",
                stdin=p5.stdout, stdout=PIPE, shell=True)
            cpu_process = p6.stdout.read().splitlines()
            # cpu_process = os.popen(
            #    "ps aux|grep -v PID|sort -rn -k +3|head|awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'|grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'").readlines()
            for pro in cpu_process:
                pro_info = pro.strip().split(' ', 4)
                # cpu使用超过标准
                if float(pro_info[2]) > self.cpu:
                    malice_result(self.name, u'CPU overload scan', '', pro_info[1],
                                  u'process use CPU too much，process：%s' % pro_info[4].replace("\n", ""),
                                  u'[1]ps -efwww', u'risk', programme=u'kill %s #kill malicious process' % pro_info[1])
                    suspicious = True
                # 内存使用超过标准
                if float(pro_info[3]) > self.mem:
                    malice_result(self.name, u'memory overload scan ', '', pro_info[1],
                                  u'process use too much memory ，process：%s' % pro_info[4].replace("\n", ""),
                                  u'[1]ps -efwww', u'risk', programme=u'kill %s #kill malicious process' % pro_info[1])
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测隐藏进程
    def check_hide_pro(self):
        suspicious, malice = False, False
        try:
            # ps获取所有pid
            p1 = Popen("ps -ef 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk 'NR>1{print $2}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            pid_process = p2.stdout.read().splitlines()

            # 所有/proc目录的pid
            pid_pro_file = []
            if not os.path.exists('/proc/'): return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    pid_pro_file.append(file)
            hids_pid = list(set(pid_pro_file).difference(set(pid_process)))
            if len(hids_pid) > 10: return suspicious, malice
            for pid in hids_pid:
                malice_result(self.name, u'hidden process scan', '', pid, u'process ID %s hidden and not show in process list' % pid,
                              u"[1] cat /proc/$$/mountinfo [2] umount /proc/%s [3]ps -ef |grep %s" % (pid, pid), u'风险',
                              programme=u'umount /proc/%s & kill %s #kill process' % (pid, pid))
                malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 查询挖矿进程、黑客工具、可疑进程名称
    def keyi_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -efwww 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("grep -E 'minerd|r00t|sqlmap|nmap|hydra|aircrack'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("grep -v 'grep'", stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p3.stdout, stdout=PIPE, shell=True)
            process = p4.stdout.read().splitlines()
            for pro in process:
                pro_info = pro.strip().split(' ', 3)
                malice_result(self.name, u'suspicious process scan', '', pro_info[1], pro_info[3].replace("\n", ""), u'[1]ps -efwww',
                              u'风险', programme=u'kill %s #kill suspicious process' % pro_info[1])
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n begin process scan')
        file_write(u'\n begin process scan\n')

        string_output(u' [1] CPU and memory check')
        suspicious, malice = self.work_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [2] hidden process scan ')
        suspicious, malice = self.check_hide_pro()
        result_output_tag(suspicious, malice)

        string_output(u' [3] reverse shell process scan ')
        suspicious, malice = self.shell_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [4] malicious process scan ')
        suspicious, malice = self.keyi_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [5] exe process scan ')
        suspicious, malice = self.exe_analysis()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Proc_Analysis()
    infos.run()
