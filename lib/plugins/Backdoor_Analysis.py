# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re
from lib.core.common import *
from lib.core.ip.ip import *
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 常规类backdoor check
# 1、LD_PRELOADbackdoor check
# 2、LD_AOUT_PRELOADbackdoor check
# 3、LD_ELF_PRELOADbackdoor check
# 4、LD_LIBRARY_PATHbackdoor check
# 5、ld.so.preloadbackdoor check
# 6、PROMPT_COMMANDbackdoor check
# 7、cronbackdoor check
# 8、aliasbackdoor
# 9、sshbackdoor ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
# 10、SSH Server wrapper backdoor，替换/user/sbin/sshd 为脚本文件
# 11、/etc/inetd.conf backdoor
# 12、/etc/xinetd.conf/backdoor
# 13、setuid类backdoor
# 14、/etc/fstab类backdoor（待写）
# 13、系统启动项backdoor check


class Backdoor_Analysis:
    def __init__(self):
        # 异常backdoor列表
        self.backdoor = []
        self.name = 'Backdoor_Analysis'

    #  check配置文件是否存在恶意配置
    def check_conf(self, tag, file, mode='only'):
        try:
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            if mode == 'only':
                with open(file) as f:
                    for line in f:
                        if len(line) < 3: continue
                        if line[0] == '#': continue
                        if 'export ' + tag in line:
                            return line
            else:
                return analysis_file(file)
            return ""
        except:
            return ""

    #  check所有环境变量，是否存在恶意配置
    def check_tag(self, name, tag, mode='only'):
        suspicious, malice = False, False
        try:
            files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/root/.tcshrc',
                     '/etc/bashrc', '/etc/profile', '/etc/profile.d/', '/etc/csh.login', '/etc/csh.cshrc']
            home_files = ['/.bashrc', '/.bash_profile', '/.tcshrc', '/.cshrc', '/.tcshrc']

            # 循环用户目录查看环境设置
            for dir in os.listdir('/home/'):
                for home_file in home_files:
                    file = os.path.join('%s%s%s' % ('/home/', dir, home_file))
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result(self.name, name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file), 'suspicious',
                                      programme=u'vi %s #delete %s setting' % (file, tag))
                        suspicious = True
            # 检查系统目录的配置
            for file in files:
                # 如果为目录形式，则遍历目录下所有文件
                if os.path.isdir(file):
                    for file in gci(file):
                        info = self.check_conf(tag, file, mode)
                        if info:
                            malice_result(self.name, name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file),
                                          'suspicious')
                            suspicious = True
                else:
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result(self.name, name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file), 'suspicious',
                                      programme=u'vi %s #delete %s setting' % (file, tag))
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_PRELOADbackdoor check
    def check_LD_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_PRELOAD backdoor', 'LD_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_AOUT_PRELOADbackdoor check
    def check_LD_AOUT_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_AOUT_PRELOAD backdoor', 'LD_AOUT_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_ELF_PRELOADbackdoor check
    def check_LD_ELF_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_ELF_PRELOAD backdoor', 'LD_ELF_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_LIBRARY_PATHbackdoor check
    def check_LD_LIBRARY_PATH(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_LIBRARY_PATH backdoor', 'LD_LIBRARY_PATH')
            return suspicious, malice
        except:
            return suspicious, malice

    # PROMPT_COMMANDbackdoor check
    def check_PROMPT_COMMAND(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'PROMPT_COMMAND backdoor', 'PROMPT_COMMAND')
            return suspicious, malice
        except:
            return suspicious, malice

    # 未知环境变量backdoor
    def check_export(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'unknown environment variable  backdoor', 'PATH', mode='all')
            return suspicious, malice
        except:
            return suspicious, malice

    # ld.so.preloadbackdoor check
    def check_ld_so_preload(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/ld.so.preload'): return suspicious, malice
            with open('/etc/ld.so.preload') as f:
                for line in f:
                    if not len(line) > 3: continue
                    if line[0] != '#':
                        content = analysis_strings(line)
                        if content:
                            malice_result(self.name, u'ld.so.preload backdoor', '/etc/ld.so.preload', '', content,
                                          '[1]cat /etc/ld.so.preload', u'risk', programme=u'vi ld.so.preload #delete so setting')
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析cron定时任务backdoor
    def check_cron(self):
        suspicious, malice = False, False
        try:
            cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/',
                             '/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron in cron_dir_list:
                for file in gci(cron):
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    for i in open(file, 'r'):
                        content = analysis_strings(i)
                        if content:
                            malice_result(self.name, u'cron backdoor', file, '', content, '[1]cat %s' % file, u'risk',
                                          programme=u'vi %s #delete malicious cron entry setting ' % file)
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析SSHbackdoor
    def check_SSH(self):
        suspicious, malice = False, False
        try:
            infos = os.popen(
                "netstat -ntpl 2>/dev/null |grep -v ':22 '| awk '{if (NR>2){print $7}}'").read().splitlines()
            for info in infos:
                pid = info.split("/")[0]
                if os.path.exists('/proc/%s/exe' % pid):
                    if 'sshd' in os.readlink('/proc/%s/exe' % pid):
                        malice_result(self.name, u'SSH backdoor', u'/porc/%s/exe' % pid, pid, u"none port 22 sshd",
                                      u'[1]ls -l /porc/%s [2]ps -ef|grep %s|grep -v grep' % (pid, pid), u'risk',
                                      programme=u'kill %s #kill malicious sshd process' % pid)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析SSH Server wrapper backdoor
    def check_SSHwrapper(self):
        suspicious, malice = False, False
        try:
            infos = os.popen("file /usr/sbin/sshd 2>/dev/null").read().splitlines()
            if not len(infos): return suspicious, malice
            if ('ELF' not in infos[0]) and ('executable' not in infos[0]):
                malice_result(self.name, u'SSHwrapper backdoor', u'/usr/sbin/sshd', "", u"/usr/sbin/sshd be modify",
                              u'[1]file /usr/sbin/sshd [2]cat /usr/sbin/sshd', u'风险',
                              programme=u'rm /usr/sbin/sshd & yum -y install openssh-server & service sshd start #delete sshd file ，reinstall ssh')
                malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析inetdbackdoor
    def check_inetd(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/inetd.conf'): return suspicious, malice
            with open('/etc/inetd.conf') as f:
                for line in f:
                    content = analysis_strings(line)
                    if content:
                        malice_result(self.name, u'inetd.conf backdoor', u'/etc/inetd.conf', '', content,
                                      u'[1]cat /etc/inetd.conf', u'risk', programme=u'vi /etc/inetd.conf #delete malicious entry in inetd.conf')
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析xinetdbackdoor
    def check_xinetd(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/xinetd.conf/'): return suspicious, malice
            for file in os.listdir('/etc/xinetd.conf/'):
                with open(os.path.join('%s%s' % ('/etc/xinetd.conf/', file))) as f:
                    for line in f:
                        content = analysis_strings(line)
                        if content:
                            malice_result(self.name, u'xinetd.conf backdoor', u'/etc/xinetd.conf', '', content,
                                          u'[1]cat /etc/xinetd.conf', u'risk', programme=u'vi /etc/xinetd.conf #delete malicious entry in xinetd.conf')
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析setuidbackdoor后
    def check_setuid(self):
        suspicious, malice = False, False
        try:
            file_infos = os.popen(
                "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null | grep -vE 'pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'").read().splitlines()
            for info in file_infos:
                malice_result(self.name, u'setuid backdoor', info, '',
                              u'file %s have setuid，shoule be root permission only ' % info, u'[1]ls -l %s' % info, u'risk',
                              programme=u'chmod u-s %s #disable setuid permission' % info)
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 系统启动项 check
    def check_startup(self):
        suspicious, malice = False, False
        try:
            init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local', '/usr/local/etc/rc.d',
                         '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab', '/etc/systemd/system']
            for path in init_path:
                if not os.path.exists(path): continue
                if os.path.isfile(path):
                    content = analysis_file(path)
                    if content:
                        malice_result(self.name, u'system startup backdoor', path, '', content, u'[1]cat %s' % path, u'risk',
                                      programme=u'vi %s #delete malicious entry' % path)
                        malice = True
                    continue
                for file in gci(path):
                    content = analysis_file(file)
                    if content:
                        malice_result(self.name, u'system startup backdoor', path, '', content, u'[1]cat %s' % path, u'risk',
                                      programme=u'vi %s #delete malicious entry' % path)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n begin backdoor scan')
        file_write(u'\nbegin backdoor scan\n')

        string_output(u' [1] LD_PRELOAD backdoor check')
        suspicious, malice = self.check_LD_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [2] LD_AOUT_PRELOAD backdoor check')
        suspicious, malice = self.check_LD_AOUT_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [3] LD_ELF_PRELOAD backdoor check')
        suspicious, malice = self.check_LD_ELF_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [4] LD_LIBRARY_PATH backdoor check')
        suspicious, malice = self.check_LD_LIBRARY_PATH()
        result_output_tag(suspicious, malice)

        string_output(u' [5] ld.so.preload backdoor check')
        suspicious, malice = self.check_ld_so_preload()
        result_output_tag(suspicious, malice)

        string_output(u' [6] PROMPT_COMMAND backdoor check')
        suspicious, malice = self.check_PROMPT_COMMAND()
        result_output_tag(suspicious, malice)

        string_output(u' [7] cron job backdoor check')
        suspicious, malice = self.check_cron()
        result_output_tag(suspicious, malice)

        string_output(u' [8] unknown environment variable backdoor check')
        suspicious, malice = self.check_export()
        result_output_tag(suspicious, malice)

        string_output(u' [9] ssh backdoor check')
        suspicious, malice = self.check_SSH()
        result_output_tag(suspicious, malice)

        string_output(u' [10] SSH wrapper backdoor check')
        suspicious, malice = self.check_SSHwrapper()
        result_output_tag(suspicious, malice)

        string_output(u' [11] inetd.conf backdoor check')
        suspicious, malice = self.check_inetd()
        result_output_tag(suspicious, malice)

        string_output(u' [12] xinetd.conf backdoor check')
        suspicious, malice = self.check_xinetd()
        result_output_tag(suspicious, malice)

        string_output(u' [13] setuid backdoor check')
        suspicious, malice = self.check_setuid()
        result_output_tag(suspicious, malice)

        string_output(u' [14] system startup backdoor check')
        suspicious, malice = self.check_startup()
        result_output_tag(suspicious, malice)

        # 结果内容输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Backdoor_Analysis()
    infos.run()
