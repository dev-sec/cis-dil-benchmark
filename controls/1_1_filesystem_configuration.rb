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

cis_level = input('cis_level')

title '1.1 Filesystem Configuration'

control 'cis-dil-benchmark-1.1.1.1' do
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc  "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.1'
  tag level: 1

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.2' do
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc  "The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.2'
  tag level: 1

  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.3' do
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc  "The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.3'
  tag level: 1

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.4' do
  title 'Ensure mounting of hfs filesystems is disabled'
  desc  "The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.4'
  tag level: 1

  describe kernel_module('hfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.5' do
  title 'Ensure mounting of hfsplus filesystems is disabled'
  desc  "The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.5'
  tag level: 1

  describe kernel_module('hfsplus') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.6' do
  title 'Ensure mounting of squashfs filesystems is disabled'
  desc  "The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs). A squashfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.6'
  tag level: 1

  describe kernel_module('squashfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.7' do
  title 'Ensure mounting of udf filesystems is disabled'
  desc  "The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.7'
  tag level: 1

  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.8' do
  title 'Ensure mounting of FAT filesystems is disabled'
  desc  "The FAT filesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12, FAT16, and FAT32 all of which are supported by the vfat kernel module.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.8'
  tag level: 2

  describe kernel_module('vfat') do
    it { should_not be_loaded }
    it { should be_disabled }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.2' do
  title 'Ensure separate partition exists for /tmp'
  desc  "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.2'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.3' do
  title 'Ensure nodev option set on /tmp partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.3'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.4' do
  title 'Ensure nosuid option set on /tmp partition'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.4'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'nosuid' }
  end
end

control 'cis-dil-benchmark-1.1.5' do
  title 'Ensure noexec option set on /tmp partition'
  desc "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.5'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'noexec' }
  end
end

control 'cis-dil-benchmark-1.1.6' do
  title 'Ensure separate partition exists for /var'
  desc  "The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.\n\nRationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.6'
  tag level: 2

  describe mount('/var') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.7' do
  title 'Ensure separate partition exists for /var/tmp'
  desc  "The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.7'
  tag level: 2

  describe mount('/var/tmp') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.8' do
  title 'Ensure nodev option set on /var/tmp partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.8'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'nodev' }
  end

end

control 'cis-dil-benchmark-1.1.9' do
  title 'Ensure nosuid option set on /var/tmp partition'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.9'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'nosuid' }
  end

end

control 'cis-dil-benchmark-1.1.10' do
  title 'Ensure noexec option set on /var/tmp partition'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.10'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'noexec' }
  end

end

control 'cis-dil-benchmark-1.1.11' do
  title 'Ensure separate partition exists for /var/log'
  desc  "The /var/log directory is used by system services to store log data .\n\nRationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.11'
  tag level: 2

  describe mount('/var/log') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.12' do
  title 'Ensure separate partition exists for /var/log/audit'
  desc  "The auditing daemon, auditd, stores log data in the /var/log/audit directory.\n\nRationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog) consume space in the same partition as auditd, it may not perform as desired."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.12'
  tag level: 2

  only_if { cis_level == 2 }

  describe mount('/var/log/audit') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.13' do
  title 'Ensure separate partition exists for /home'
  desc  "The /home directory is used to support disk storage needs of local users.\n\nRationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.13'
  tag level: 2

  only_if { cis_level == 2 }

  describe mount('/home') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.14' do
  title 'Ensure nodev option set on /home partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.14'
  tag level: 1

  only_if('/home is mounted') do
    mount('/home').mounted?
  end

  describe mount('/home') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.15' do
  title 'Ensure nodev option set on /dev/shm partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.15'
  tag level: 1

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end

  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.16' do
  title 'Ensure nosuid option set on /dev/shm partitionrun'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.16'
  tag level: 1

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end

  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

control 'cis-dil-benchmark-1.1.17' do
  title 'Ensure noexec option set on /dev/shm partition'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.17'
  tag level: 1

  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end
end

control 'cis-dil-benchmark-1.1.18' do
  title 'Ensure nodev option set on removable media partitions'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.18'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.18' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.19' do
  title 'Ensure nosuid option set on removable media partitions'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.19'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.19' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.20' do
  title 'Ensure noexec option set on removable media partitions'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from the removable media. This deters users from being able to introduce potentially malicious software on the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.20'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.20' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.21' do
  title 'Ensure sticky bit is set on all world-writable directories'
  desc  "Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.\n\nRationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.21'
  tag level: 1

  describe command("df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)") do
    its('stdout') { should cmp '' }
  end
end

control 'cis-dil-benchmark-1.1.22' do
  title 'Disable Automounting'
  desc  "autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.\n\nRationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.22'
  tag level: 1

  describe.one do
    describe service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end

    describe systemd_service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-1.1.23' do
  title 'Disable USB Storage'
  desc  '
    USB storage provides a means to transfer and store files insuring persistence and availability of the files independent of network connection status.
    Its popularity and utility has led to USB-based malware being a simple and common means for network infiltration and a first step to establishing
    a persistent threat within a networked environment.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.23'
  tag level: 1

  # kernel modules need to use underscores
  # ref: https://github.com/inspec/inspec/issues/5190
  describe kernel_module('usb_storage') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end
