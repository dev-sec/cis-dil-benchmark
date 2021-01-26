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

expected_gid = 0
expected_gid = 42 if os.debian? || os.suse? || os.name == 'alpine'

title '6.1 System File Permissions'

control 'cis-dil-benchmark-6.1.1' do
  title 'Audit system file permissions'
  desc  '
    The RPM and Debian package manager have a number of useful options. One of these, the --verify
    (or -v for RPM) option, can be used to verify that system packages are correctly installed. The --verify
    option can be used to verify a particular package or to verify all system packages. If no output is
    returned, the package is installed correctly. The following table describes the meaning of output
    from the verify option:

    Code Meaning
    S File size differs.
    M File mode differs (includes permissions and file type).
    5 The MD5 checksum differs.
    D The major and minor version numbers differ on a device file.
    L A mismatch occurs in a link.
    U The file ownership differs.
    G The file group owner differs.
    T The file time (mtime) differs.

    The `rpm -qf` or `dpkg -S` command can be used to determine which package a particular file belongs to.
    For example the following commands determines which package the /bin/bash file belongs to:
    ```shell-session
    # rpm -qf /bin/bash
    bash-4.1.2-29.el6.x86_64

    # dpkg -S /bin/bash
    bash: /bin/bash
    ```

    To verify the settings for the package that controls the /bin/bash file, run the following:
    ```shell-session
    # rpm -V bash-4.1.2-29.el6.x86_64
    .M.......    /bin/bash

    # dpkg --verify bash
    ??5?????? c /etc/bash.bashrc
    ```

    Note that you can feed the output of the rpm -qf command to the rpm -V command:
    ```shell-session
    # rpm -V `rpm -qf /etc/passwd`
    .M...... c /etc/passwd\nS.5....T c /etc/printcap
   ```
    Rationale:
    It is important to confirm that packaged system files and directories are maintained with the permissions
    they were intended to have from the OS vendor.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:6.1.1'
  tag level: 2

  only_if {  cis_level == 2 }

  describe 'cis-dil-benchmark-6.1.1' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-6.1.2' do
  title 'Ensure permissions on /etc/passwd are configured'
  desc  '
    The /etc/passwd file contains user account information that is used by many system utilities and
    therefore must be readable for these utilities to operate.

    Rationale:

    It is critical to ensure that the /etc/passwd file is protected from unauthorized write access.
    Although it is protected by default, the file permissions could be changed either inadvertently or
    through malicious actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.2'
  tag level: 1

  passwd_files = ['/etc/passwd']
  passwd_files << '/usr/share/baselayout/passwd' if file('/etc/nsswitch.conf').content =~ /^passwd:\s+(\S+\s+)*usrfiles/

  passwd_files.each do |f|
    describe file(f) do
      it { should exist }
      its('mode') { should cmp '0644' }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
      its('sticky') { should equal false }
      its('suid') { should equal false }
      its('sgid') { should equal false }
    end
  end
end

control 'cis-dil-benchmark-6.1.3' do
  title 'Ensure permissions on /etc/shadow are configured'
  desc  '
    The /etc/shadow file is used to store the information about user accounts that is critical to the security
    of those accounts, such as the hashed password and other security information.

    Rationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program
    against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration)
    could also be useful to subvert the user accounts.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.3'
  tag level: 1

  shadow_files = ['/etc/shadow']
  shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

  shadow_files.each do |f|
    describe file(f) do
      it { should exist }
      it { should_not be_more_permissive_than('0640') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp expected_gid }
    end
  end
end

control 'cis-dil-benchmark-6.1.4' do
  title 'Ensure permissions on /etc/group are configured'
  desc  '
    The /etc/group file contains a list of all the valid groups defined in the system. The command below allows
    read/write access for root and read access for everyone else.

    Rationale:

    The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to
    be readable as this information is used with many non-privileged programs.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.4'
  tag level: 1

  group_files = ['/etc/group']
  group_files << '/usr/share/baselayout/group' if file('/etc/nsswitch.conf').content =~ /^group:\s+(\S+\s+)*usrfiles/

  group_files.each do |f|
    describe file(f) do
      it { should exist }
      its('mode') { should cmp '0644' }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  end
end

control 'cis-dil-benchmark-6.1.5' do
  title 'Ensure permissions on /etc/gshadow are configured'
  desc  '
    The /etc/gshadow file is used to store the information about groups that is critical to the security of
    those accounts, such as the hashed password and other security information.

    Rationale:

    If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program
    against the hashed password to break it. Other security information that is stored in the /etc/gshadow file
    (such as group administrators) could also be useful to subvert the group.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.5'
  tag level: 1

  gshadow_files = ['/etc/gshadow']
  gshadow_files << '/usr/share/baselayout/gshadow' if file('/etc/nsswitch.conf').content =~ /^gshadow:\s+(\S+\s+)*usrfiles/

  gshadow_files.each do |f|
    describe file(f) do
      it { should exist }
      it { should_not be_more_permissive_than('0640') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp expected_gid }
    end
  end
end

control 'cis-dil-benchmark-6.1.6' do
  title 'Ensure permissions on /etc/passwd- are configured'
  desc  '
    The /etc/passwd- file contains backup user account information.

    Rationale:

    It is critical to ensure that the /etc/passwd- file is protected from unauthorized access.
    Although it is protected by default, the file permissions could be changed either inadvertently or
    through malicious actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.6'
  tag level: 1

  describe file('/etc/passwd-') do
    it { should exist }
    it { should_not be_more_permissive_than('0600') }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-6.1.7' do
  title 'Ensure permissions on /etc/shadow- are configured'
  desc  '
    The  /etc/shadow-  file is used to store backup information about user accounts that is critical to the security
    of those accounts, such as the hashed password and other security information.

    Rationale:
    It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is
    protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.7'
  tag level: 1

  describe file('/etc/shadow-') do
    it { should exist }
    it { should_not be_more_permissive_than('0640') }

    its('uid') { should cmp 0 }
    its('gid') { should cmp expected_gid }
  end
end

control 'cis-dil-benchmark-6.1.8' do
  title 'Ensure permissions on /etc/group- are configured'
  desc  '
    The /etc/group- file contains a backup list of all the valid groups defined in the system.

    Rationale:

    It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it
    is protected by default, the file permissions could be changed either inadvertently or through malicious
    actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.8'
  tag level: 1

  describe file('/etc/group-') do
    it { should exist }
    it { should_not be_more_permissive_than('0644') }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-6.1.9' do
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc  '
    The /etc/gshadow- file is used to store backup information about groups that is critical to
    the security of those accounts, such as the hashed password and other security information.

    Rationale:

    It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it
    is protected by default, the file permissions could be changed either inadvertently or through malicious
    actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.9'
  tag level: 1

  describe file('/etc/gshadow-') do
    it { should exist }
    it { should_not be_more_permissive_than('0640') }
    its('uid') { should cmp 0 }
    its('gid') { should cmp expected_gid }
  end
end

control 'cis-dil-benchmark-6.1.10' do
  title 'Ensure no world writable files exist'
  desc  '
    Unix-based systems support variable settings to control access to files. World writable files are the
    least secure. See the chmod(2) man page for more information.

    Rationale:

    Data in world-writable files can be modified and compromised by any user on the system. World writable
    files may also indicate an incorrectly written script or program that could potentially be the cause of
    a larger compromise to the system\'s integrity.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.10'
  tag level: 1

  describe command("df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -type f -perm -0002") do
    its('stdout') { should cmp '' }
  end
end

control 'cis-dil-benchmark-6.1.11' do
  title 'Ensure no unowned files or directories exist'
  desc  '
    Sometimes when administrators delete users from the password file they neglect to remove all files owned
    by those users from the system.

    Rationale:
    A new user who is assigned the deleted user\'s user ID or group ID may then end up "owning" these files,
    and thus have more access on the system than was intended.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.11'
  tag level: 1

  describe command("df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -nouser") do
    its('stdout') { should cmp '' }
  end
end

control 'cis-dil-benchmark-6.1.12' do
  title 'Ensure no ungrouped files or directories exist'
  desc  '
    Sometimes when administrators delete users or groups from the system they neglect to remove all files
    owned by those users or groups.

    Rationale: A new user who is assigned the deleted user\'s user ID or group ID may then end up "owning"
    these files, and thus have more access on the system than was intended.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.1.12'
  tag level: 1

  describe command("df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -nogroup") do
    its('stdout') { should cmp '' }
  end
end

control 'cis-dil-benchmark-6.1.13' do
  title 'Audit SUID executables'
  desc  '
    The owner of a file can set the file\'s permissions to run with the owner\'s or group\'s permissions,
    even if the user running the program is not the owner or a member of the group. The most common reason
    for a SUID program is to enable users to perform functions (such as changing their password) that require
    root privileges.

    Rationale: There are valid reasons for SUID programs, but it is important to identify and review such
    programs to ensure they are legitimate.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:6.1.13'
  tag level: 1

  describe 'cis-dil-benchmark-6.1.13' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-6.1.14' do
  title 'Audit SGID executables'
  desc  '
    The owner of a file can set the file\'s permissions to run with the owner\'s or group\'s permissions,
    even if the user running the program is not the owner or a member of the group. The most common
    reason for a SGID program is to enable users to perform functions (such as changing their password)
    that require root privileges.

    Rationale:
    There are valid reasons for SGID programs, but it is important to identify and review such programs to
    ensure they are legitimate. Review the files returned by the action in the audit section and check to see
    if system binaries have a different md5 checksum than what from the package. This is an indication that
    the binary may have been replaced.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:6.1.14'
  tag level: 1

  describe 'cis-dil-benchmark-6.1.14' do
    skip 'Not implemented'
  end
end
