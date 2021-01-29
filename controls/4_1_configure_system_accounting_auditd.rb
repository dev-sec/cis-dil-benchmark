# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

cis_level = attribute('cis_level')

title '4.1 Configure System Accounting (auditd)'

uid_min = login_defs.UID_MIN.to_i

control 'cis-dil-benchmark-4.1.1.1' do
  title 'Ensure audit log storage size is configured'
  desc  "Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.\n\nRationale: It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost."

  tag cis: 'distribution-independent-linux:4.1.1.1'
  tag level: 2

  impact 0.0

  only_if { cis_level == 2 }

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file = \d+\s*(?:#.*)?$/) }
  end
end

control 'cis-dil-benchmark-4.1.1.2' do
  title 'Ensure system is disabled when audit logs are full'
  desc  "The auditd daemon can be configured to halt the system when the audit logs are full.\n\nRationale: In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.1.2'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^space_left_action = email\s*(?:#.*)?$/) }
    its('content') { should match(/^action_mail_acct = root\s*(?:#.*)?$/) }
    its('content') { should match(/^admin_space_left_action = halt\s*(?:#.*)?$/) }
  end
end

control 'cis-dil-benchmark-4.1.1.3' do
  title 'Ensure audit logs are not automatically deleted'
  desc  "The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.\n\nRationale: In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.1.3'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file_action = keep_logs\s*(?:#.*)?$/) }
  end
end

control 'cis-dil-benchmark-4.1.2' do
  title 'Ensure auditd is installed'
  desc  "auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk\n\nRationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.2'
  tag level: 2

  only_if { cis_level == 2 }

  describe.one do
    %w[audit auditd].each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end
  end

  describe.one do
    %w[audit-libs audispd-plugins].each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end
  end
end

control 'cis-dil-benchmark-4.1.3' do
  title 'Ensure auditd service is enabled'
  desc  "Turn on the auditd daemon to record system events.\n\nRationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.3'
  tag level: 2

  only_if { cis_level == 2 }

  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

control 'cis-dil-benchmark-4.1.4' do
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc  "Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.\n\nRationale: Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.4'
  tag level: 2

  only_if { cis_level == 2 }

  describe.one do
    grub_conf.locations.each do |f|
      describe file(f) do
        its('content') { should match(/audit=1/) }
      end
    end
  end
end

control 'cis-dil-benchmark-4.1.5' do
  title 'Ensure events that modify date and time information are collected'
  desc  "Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon exit, tagging the records with the identifier \"time-change\"\n\nRationale: Unexpected changes in system date and/or time could be a sign of malicious activity on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.5'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change$/) }
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S clock_settime -k time-change$/) }
    its('content') { should match %r{^-w /etc/localtime -p wa -k time-change$} }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S adjtimex -S settimeofday -k time-change$/) }
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S clock_settime -k time-change$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.6' do
  title 'Ensure events that modify user/group information are collected'
  desc  "Record events affecting the group, passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.\n\nRationale: Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.6'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /etc/group -p wa -k identity$}) }
    its('content') { should match(%r{^-w /etc/passwd -p wa -k identity$}) }
    its('content') { should match(%r{^-w /etc/gshadow -p wa -k identity$}) }
    its('content') { should match(%r{^-w /etc/shadow -p wa -k identity$}) }
    its('content') { should match(%r{^-w /etc/security/opasswd -p wa -k identity$}) }
  end
end

control 'cis-dil-benchmark-4.1.7' do
  title "Ensure events that modify the system's network environment are collected"
  desc  "Record changes to network environment files or system calls. The below parameters monitor the sethostname (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages displayed pre-login), /etc/hosts (file containing host names and associated IP addresses) and /etc/sysconfig/network (directory containing network interface scripts and configurations) files.\n\nRationale: Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname of a system. The changing of these names could potentially break security parameters that are set based on those names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with the identifier \"system-locale.\""
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.7'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S sethostname -S setdomainname -k system-locale$/) }
    its('content') { should match(%r{^-w /etc/issue -p wa -k system-locale$}) }
    its('content') { should match(%r{^-w /etc/issue\.net -p wa -k system-locale$}) }
    its('content') { should match(%r{^-w /etc/hosts -p wa -k system-locale$}) }
    its('content') { should match %r{^-w /etc/sysconfig/network -p wa -k system-locale$} }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S sethostname -S setdomainname -k system-locale$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.8' do
  title "Ensure events that modify the system's Mandatory Access Controls are collected"
  desc  "Monitor SELinux/AppArmor mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/selinux or /etc/apparmor and /etc/apparmor.d directories.\n\nRationale: Changes to files in these directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.8'
  tag level: 2

  only_if { cis_level == 2 }

  describe.one do
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(%r{^-w /etc/selinux/ -p wa -k MAC-policy$}) }
      its('content') { should match(%r{^-w /usr/share/selinux/ -p wa -k MAC-policy$}) }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(%r{^-w /etc/apparmor/ -p wa -k MAC-policy$}) }
      its('content') { should match(%r{^-w /etc/apparmor.d/ -p wa -k MAC-policy$}) }
    end
  end
end

control 'cis-dil-benchmark-4.1.9' do
  title 'Ensure login and logout events are collected'
  desc  "Monitor login and logout events. The parameters below track changes to files associated with login/logout events. The file /var/log/faillog tracks failed events from login. The file /var/log/lastlog maintain records of the last time a user successfully logged in. The file /var/log/tallylog maintains records of failures via the pam_tally2 module\n\nRationale: Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.9'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /var/log/faillog -p wa -k logins$}) }
    its('content') { should match(%r{^-w /var/log/lastlog -p wa -k logins$}) }
    its('content') { should match(%r{^-w /var/log/tallylog -p wa -k logins$}) }
  end
end

control 'cis-dil-benchmark-4.1.10' do
  title 'Ensure session initiation information is collected'
  desc  "Monitor session initiation events. The parameters in this section track changes to the files associated with session events. The file /var/run/utmp file tracks all currently logged in users. The /var/log/wtmp file tracks logins, logouts, shutdown, and reboot events. All audit records will be tagged with the identifier \"session.\" The file /var/log/btmp keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp. All audit records will be tagged with the identifier \"logins.\"\n\nRationale: Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in)."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.10'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /var/run/utmp -p wa -k session$}) }
    its('content') { should match(%r{^-w /var/log/wtmp -p wa -k logins$}) }
    its('content') { should match(%r{^-w /var/log/btmp -p wa -k logins$}) }
  end
end

control 'cis-dil-benchmark-4.1.11' do
  title 'Ensure discretionary access control permission modification events are collected'
  desc  "Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The chmod, fchmod and fchmodat system calls affect the permissions associated with a file. The chown, fchown, fchownat and lchown system calls affect owner and group attributes on a file. The setxattr, lsetxattr, fsetxattr (set extended file attributes) and removexattr, lremovexattr, fremovexattr (remove extended file attributes) control extended file attributes. In all cases, an audit record will only be written for non-system user ids (auid >= 500) and will ignore Daemon events (auid = 4294967295). All audit records will be tagged with the identifier \"perm_mod.\"\n\nRationale: Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.10'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=#{uid_min} -F auid!=4294967295 -k perm_mod$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.12' do
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  desc  "Monitor for unsuccessful attempts to access files. The parameters below are associated with system calls that control creation (creat), opening (open, openat) and truncation (truncate, ftruncate) of files. An audit log record will only be written if the user is a non-privileged user (auid > = 500), is not a Daemon event (auid=4294967295) and if the system call returned EACCES (permission denied to the file) or EPERM (some other permanent error associated with the specific system call). All audit records will be tagged with the identifier \"access.\"\n\nRationale: Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.12'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=#{uid_min} -F auid!=4294967295 -k access$/) }
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=#{uid_min} -F auid!=4294967295 -k access$/) }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=#{uid_min} -F auid!=4294967295 -k access$/) }
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=#{uid_min} -F auid!=4294967295 -k access$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.13' do
  title 'Ensure use of privileged commands is collected'
  desc  "Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.\n\nRationale: Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.13'
  tag level: 2

  only_if { cis_level == 2 }

  command('find / -xdev \( -perm -4000 -o -perm -2000 \) -type f').stdout.split.map { |x| "^-a (always,exit|exit,always) -F path=#{x} -F perm=x -F auid>=#{uid_min} -F auid!=4294967295 -k privileged$" }.each do |entry|
    describe file('/etc/audit/audit.rules') do
      its('content') { should match Regexp.new(entry) }
    end
  end
end

control 'cis-dil-benchmark-4.1.14' do
  title 'Ensure successful file system mounts are collected'
  desc  "Monitor the use of the mount system call. The mount (and umount) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user\n\nRationale: It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful open, creat and truncate system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.14'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S mount -F auid>=#{uid_min} -F auid!=4294967295 -k mounts$/) }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S mount -F auid>=#{uid_min} -F auid!=4294967295 -k mounts$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.15' do
  title 'Ensure file deletion events by users are collected'
  desc  "Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for the unlink (remove a file), unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) system calls and tags them with the identifier \"delete\".\n\nRationale: Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.15'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=#{uid_min} -F auid!=4294967295 -k delete$/) }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=#{uid_min} -F auid!=4294967295 -k delete$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.16' do
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc  "Monitor scope changes for system administrations. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers will be written to when the file or its attributes have changed. The audit records will be tagged with the identifier \"scope.\"\n\nRationale: Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope of system administrator activity."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.16'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /etc/sudoers -p wa -k scope$}) }
    its('content') { should match(%r{^-w /etc/sudoers\.d/? -p wa -k scope$}) }
  end
end

control 'cis-dil-benchmark-4.1.17' do
  title 'Ensure system administrator actions (sudolog) are collected'
  desc  "Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log.\n\nRationale: Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.17'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /var/log/sudo\.log -p wa -k actions$}) }
  end
end

control 'cis-dil-benchmark-4.1.18' do
  title 'Ensure kernel module loading and unloading is collected'
  desc  "Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, as well as some other features) control loading and unloading of modules. The init_module (load a module) and delete_module (delete a module) system calls control loading and unloading of modules. Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of \"modules\".\n\nRationale: Monitoring the use of insmod, rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting to use a different program to load and unload modules."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.1.18'
  tag level: 2

  only_if { cis_level == 2 }

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{^-w /sbin/insmod -p x -k modules$}) }
    its('content') { should match(%r{^-w /sbin/rmmod -p x -k modules$}) }
    its('content') { should match(%r{^-w /sbin/modprobe -p x -k modules$}) }
  end

  if command('uname -m').stdout.strip == 'x86_64'
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b64 -S init_module -S delete_module -k modules$/) }
    end
  else
    describe file('/etc/audit/audit.rules') do
      its('content') { should match(/^-a (always,exit|exit,always) -F arch=b32 -S init_module -S delete_module -k modules$/) }
    end
  end
end

control 'cis-dil-benchmark-4.1.19' do
  title 'Ensure the audit configuration is immutable'
  desc  "Set system audit so that audit rules cannot be modified with auditctl. Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.\n\nRationale: In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes."
  impact 1.0

  only_if { cis_level == 2 }

  tag cis: 'distribution-independent-linux:4.1.19'
  tag level: 2

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-e 2$/) }
  end
end
