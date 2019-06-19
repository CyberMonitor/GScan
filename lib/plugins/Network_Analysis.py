# coding:utf-8
from __future__ import print_function
import os, optparse, time, subprocess, sys, json
from lib.core.ip.ip import *
from lib.core.common import *


# 作者：咚咚呛
# 分析网络连接
# 1、检查当前网络对外连接，提取国外连接
# 2、检查当前对外连接，匹配Rootkit特征
# 3、网卡混杂模式

class Network_Analysis:
    def __init__(self):
        # 可疑网络连接列表
        # 远程ip、远程端口、可疑描述
        self.network_malware = []
        self.name = u'Network_Analysis'
        self.port_malware = [
            {'protocol': 'tcp', 'port': '1524', 'description': 'Possible FreeBSD (FBRK) Rootkit backdoor'},
            {'protocol': 'tcp', 'port': '1984', 'description': 'Fuckit Rootkit'},
            {'protocol': 'udp', 'port': '2001', 'description': 'Scalper'},
            {'protocol': 'tcp', 'port': '2006', 'description': 'CB Rootkit or w00tkit Rootkit SSH server'},
            {'protocol': 'tcp', 'port': '2128', 'description': 'MRK'},
            {'protocol': 'tcp', 'port': '6666', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6667', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6668', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '6669', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '7000', 'description': 'Possible rogue IRC bot'},
            {'protocol': 'tcp', 'port': '13000', 'description': 'Possible Universal Rootkit (URK) SSH server'},
            {'protocol': 'tcp', 'port': '14856', 'description': 'Optic Kit (Tux)'},
            {'protocol': 'tcp', 'port': '25000', 'description': 'Possible Universal Rootkit (URK) component'},
            {'protocol': 'tcp', 'port': '29812', 'description': 'FreeBSD (FBRK) Rootkit default backdoor port'},
            {'protocol': 'tcp', 'port': '31337', 'description': 'Historical backdoor port'},
            {'protocol': 'tcp', 'port': '32982', 'description': 'Solaris Wanuk'},
            {'protocol': 'tcp', 'port': '33369', 'description': 'Volc Rootkit SSH server (divine)'},
            {'protocol': 'tcp', 'port': '47107', 'description': 'T0rn'},
            {'protocol': 'tcp', 'port': '47018', 'description': 'Possible Universal Rootkit (URK) component'},
            {'protocol': 'tcp', 'port': '60922', 'description': 'zaRwT.KiT'},
            {'protocol': 'tcp', 'port': '62883',
             'description': 'Possible FreeBSD (FBRK) Rootkit default backdoor port'},
            {'protocol': 'tcp', 'port': '65535', 'description': 'FreeBSD Rootkit (FBRK) telnet port'}
        ]
        # self.check_network()

    # 境外IP的链接
    def check_network_abroad(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen(
                "netstat -anp 2>/dev/null| grep ESTABLISHED | awk '{print $1\" \"$5\" \"$7}'").read().splitlines()
            for nets in shell_process:
                netinfo = nets.strip().split(' ')
                protocol = netinfo[0]
                remote_ip, remote_port = netinfo[1].replace("\n", "").split(":")
                pid, pname = netinfo[2].replace("\n", "").split("/")
                if check_ip(ip):
                    malice_result(self.name, u'oversea IP connection', '', pid,
                                  u'process %s oversea IP %s via %s connection' % (pname, remote_ip, protocol), u'[1]netstat -ano',
                                  u'suspicious', programme=u'kill %s #kill process' % pid)
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 可疑端口的链接
    def check_net_suspicious(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen(
                "netstat -anp 2>/dev/null| grep ESTABLISHED | awk '{print $1\" \"$5\" \"$7}'").read().splitlines()
            for nets in shell_process:
                netinfo = nets.strip().split(' ')
                protocol = netinfo[0]
                remote_ip, remote_port = netinfo[1].replace("\n", "").split(":")
                pid, pname = netinfo[2].replace("\n", "").split("/")
                for malware in self.port_malware:
                    if malware['port'] == remote_port:
                        malice_result(self.name, u'suspicious port ', '', pid, u'process %s connect IP%s port %s，this port common used in %s' % (
                            pname, remote_ip, remote_port, malware['description']), u'[1]netstat -ano', u'suspicious',
                                      programme=u'kill %s #kill process' % pid)
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 网卡混杂模式检测
    def check_promisc(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen("ifconfig 2>/dev/null| grep PROMISC | grep RUNNING").read().splitlines()
            if len(shell_process) > 0:
                malice_result(self.name, u'network promisc check', '', '', u'promisc mode', u'ifconfig | grep PROMISC | grep RUNNING',
                              u'suspicious', programme=u'ifconfig eth0 -promisc #close promisc mode ')
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n begin network type scan ')
        file_write(u'\nbegin network type scan\n')

        string_output(u' [1] network connection check (oversea) ')
        suspicious, malice = self.check_network_abroad()
        result_output_tag(suspicious, malice)

        string_output(u' [2] net suspicious check ')
        suspicious, malice = self.check_net_suspicious()
        result_output_tag(suspicious, malice)

        string_output(u' [3] network card promise mode check')
        suspicious, malice = self.check_promisc()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Network_Analysis()
    infos.run()
    print(u"suspicious network：")
    for info in infos.network_malware:
        print(info)
