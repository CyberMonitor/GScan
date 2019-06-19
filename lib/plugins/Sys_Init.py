# coding:utf-8
from __future__ import print_function
from subprocess import Popen, PIPE
import os
from lib.core.common import *




class SYS_INIT:
    def __init__(self):
        # 异常信息
        self.backdoor_info = []
        self.name = u'SYS_INIT'

    def check_alias_conf(self):
        suspicious, malice = False, False
        try:
            files = ['/root/.bashrc', '/root/.bash_profile', '/etc/bashrc', '/etc/profile']

            for dir in os.listdir('/home/'):
                suspicious2, malice2 = self.alias_file_analysis(os.path.join('%s%s%s' % ('/home/', dir, '/.bashrc')))
                if suspicious2: suspicious = True
                if malice2: malice = True

                suspicious2, malice2 = self.alias_file_analysis(
                    os.path.join('%s%s%s' % ('/home/', dir, '/.bash_profile')))
                if suspicious2: suspicious = True
                if malice2: malice = True

            for file in files:
                suspicious2, malice2 = self.alias_file_analysis(file)
                if suspicious2: suspicious = True
                if malice2: malice = True

            return suspicious, malice
        except:
            return suspicious, malice

    # 分析环境变量alias配置文件的信息
    def alias_file_analysis(self, file):
        suspicious, malice = False, False
        try:
            # 程序需要用到的系统命令
            syscmds = ['ps', 'strings', 'netstat', 'find', 'echo', 'iptables', 'lastlog', 'who', 'ifconfig']
            if not os.path.exists(file): return suspicious, malice
            with open(file) as f:
                for line in f:
                    if line[:5] == 'alias':
                        for syscmd in syscmds:
                            if 'alias ' + syscmd + '=' in line:
                                malice_result(self.name, u'initial alias check', file, '', u'exist suspicious alias：%s' % line,
                                              u'[1]alias [2]cat %s' % file, u'suspicious', programme=u'vi %s #delete alias suspicious setting' % file)
                                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\nalias check')
        file_write(u'\nalias check\n')

        string_output(u' [1]alias check')
        suspicious, malice = self.check_alias_conf()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    init = SYS_INIT()
    init.run()
