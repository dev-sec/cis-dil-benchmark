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

title '6.2 User and Group Settings'

uid_min = login_defs.UID_MIN.to_i

shadow_files = ['/etc/shadow']
shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

passwd_files = ['/etc/passwd']
passwd_files << '/usr/share/baselayout/passwd' if file('/etc/nsswitch.conf').content =~ /^passwd:\s+(\S+\s+)*usrfiles/

group_files = ['/etc/group']
group_files << '/usr/share/baselayout/group' if file('/etc/nsswitch.conf').content =~ /^group:\s+(\S+\s+)*usrfiles/

control 'cis-dil-benchmark-6.2.1' do
  title 'Ensure password fields are not empty'
  desc  '
    An account with an empty password field means that anybody may log in as that user without providing a password.

    Rationale
    All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.1'
  tag level: 1

  shadow_files.each do |f|
    describe shadow(f) do
      its('passwords') { should_not include '' }
    end
  end
end

control 'cis-dil-benchmark-6.2.2' do
  title 'Ensure no legacy "+" entries exist in /etc/passwd'
  desc  '
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file.
    These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.

    Rationale:
    These entries may provide an avenue for attackers to gain privileged access on the system.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.2'
  tag level: 1

  passwd_files.each do |f|
    describe passwd(f) do
      its('users') { should_not include '+' }
    end
  end
end

control 'cis-dil-benchmark-6.2.3' do
  title 'Ensure no legacy "+" entries exist in /etc/shadow'
  desc  '
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system
    configuration file. These entries are no longer required on most systems, but may exist in files that have been imported
    from other platforms.

    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.3'
  tag level: 1

  shadow_files.each do |f|
    describe shadow(f) do
      its('users') { should_not include '+' }
    end
  end
end

control 'cis-dil-benchmark-6.2.4' do
  title 'Ensure no legacy "+" entries exist in /etc/group'
  desc  '
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system
    configuration file. These entries are no longer required on most systems, but may exist in files that have been imported
    from other platforms.

    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.4'
  tag level: 1

  group_files.each do |f|
    describe etc_group(f) do
      its('groups') { should_not include '+' }
    end
  end
end

control 'cis-dil-benchmark-6.2.5' do
  title 'Ensure root is the only UID 0 account'
  desc  '
    Any account with UID 0 has superuser privileges on the system.

    Rationale: This access must be limited to only the default root account and only from the system console.
    Administrative access must be through an unprivileged account using an approved mechanism as noted in
    Item 5.6 Ensure access to the su command is restricted.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.5'
  tag level: 1

  passwd_files.each do |f|
    describe passwd(f).uids(0) do
      its('users') { should cmp ['root'] }
    end
  end
end

control 'cis-dil-benchmark-6.2.6' do
  title 'Ensure root PATH Integrity'
  desc  '
    The root user can execute any command on the system and could be fooled into executing programs unintentionally if
    the PATH is not set correctly.

    Rationale: Including the current working directory (.) or other writable directory in root\'s executable path makes it
    likely that an attacker can gain superuser access by forcing an administrator operating as root to execute
    a Trojan horse program.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.6'
  tag level: 1

  root_path = os_env('PATH').split

  describe root_path do
    it { should_not be_empty }
    it { should_not include '' }
    it { should_not include '.' }
  end

  root_path.each do |entry|
    describe file(entry) do
      it { should be_directory }
      it { should_not be_writable.by 'group' }
      it { should_not be_writable.by 'other' }
      its('uid') { should cmp 0 }
    end
  end
end

control 'cis-dil-benchmark-6.2.7' do
  title 'Ensure all users\' home directories exist'
  desc  '
    Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.

    Rationale: If the user\'s home directory does not exist or is unassigned, the user will be placed in "/" and will not be
    able to write any files or have local environment variables set.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.7'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).where { uid.to_i >= uid_min }.where { shell !~ %r{^(/usr/sbin/nologin|/sbin/nologin|/bin/false)$} }.homes.each do |h|
      describe file(h) do
        it { should be_directory }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.8' do
  title 'Ensure users\' home directories permissions are 750 or more restrictive'
  desc  '
    While the system administrator can establish secure permissions for users\' home directories, the users can easily override these.

    Rationale:

    Group or world-writable user home directories may enable malicious users to steal or modify other users\' data or to gain
    another user\'s system privileges.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.8'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).where { uid.to_i >= uid_min }.where { shell !~ %r{^(/usr/sbin/nologin|/sbin/nologin|/bin/false)$} }.homes.each do |h|
      describe file(h) do
        it { should exist }
        it { should_not be_writable.by 'group' }
        it { should_not be_readable.by 'other' }
        it { should_not be_writable.by 'other' }
        it { should_not be_executable.by 'other' }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.9' do
  title 'Ensure users own their home directories'
  desc  '
    The user home directory is space defined for the particular user to set local environment variables and to store
    personal files.

    Rationale:

    Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.9'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).where { uid.to_i >= uid_min }.where { shell !~ %r{^(/usr/sbin/nologin|/sbin/nologin|/bin/false)$} }.entries.each do |entry|
      describe file(entry.home) do
        it { should be_owned_by entry.user }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.10' do
  title 'Ensure users\' dot files are not group or world writable'
  desc  '
    While the system administrator can establish secure permissions for users\' "dot" files, the users can easily override these.

    Rationale:
    Group or world-writable user configuration files may enable malicious users to steal or modify other users\' data or to gain another
    user\'s system privileges.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.10'
  tag level: 1

  passwd_files.each do |pf|
    passwd(pf).where { uid.to_i >= uid_min }.where { shell !~ %r{^(/usr/sbin/nologin|/sbin/nologin|/bin/false)$} }.homes.each do |h|
      command("find #{h} -maxdepth 1 -type f -name '.*'").stdout.split.each do |f|
        describe file(f) do
          it { should_not be_writable.by 'group' }
          it { should_not be_writable.by 'other' }
        end
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.11' do
  title 'Ensure no users have .forward files'
  desc  '
    The .forward file specifies an email address to forward the user\'s mail to.

    Rationale:

    Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization.
    The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.11'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).homes.each do |home|
      describe file("#{home}/.forward") do
        it { should_not exist }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.12' do
  title 'Ensure no users have .netrc files'
  desc  '
    The .netrc file contains data for logging into a remote host for file transfers via FTP.

    Rationale:
    The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled,
    user accounts may have brought over .netrc files from other systems which could pose a risk to those systems.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.12'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).homes.each do |home|
      describe file("#{home}/.netrc") do
        it { should_not exist }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.13' do
  title 'Ensure users\' .netrc Files are not group or world accessible'
  desc  '
    While the system administrator can establish secure permissions for users\' .netrc files, the users can easily override these.

    Rationale:
    .netrc files may contain unencrypted passwords that may be used to attack other systems.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.13'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).homes.each do |home|
      next unless file("#{home}/.netrc").exist?

      it { should_not be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should_not be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
    end
  end
end

control 'cis-dil-benchmark-6.2.14' do
  title 'Ensure no users have .rhosts files'
  desc  '
    While no .rhosts files are shipped by default, users can easily create them.

    Rationale:
    This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf. Even though the .rhosts files are
    ineffective if support is disabled in /etc/pam.conf, they may have been brought over from other systems and could contain
    information useful to an attacker for those other systems.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.14'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).homes.each do |home|
      describe file("#{home}/.rhosts") do
        it { should_not exist }
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.15' do
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc  '
    Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not
    in /etc/group.

    Rationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security
    since group permissions are not properly managed.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.15'
  tag level: 1

  passwd_files.each do |f|
    passwd(f).gids.map(&:to_i).each do |gid|
      describe.one do
        group_files.each do |gf|
          describe etc_group(gf) do
            its(:gids) { should include gid }
          end
        end
      end
    end
  end
end

control 'cis-dil-benchmark-6.2.16' do
  title 'Ensure no duplicate UIDs exist'
  desc  '
    Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator
    to manually edit the /etc/passwd file and change the UID field.

    Rationale:
    Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.16'
  tag level: 1

  passwd_files.each do |f|
    describe passwd(f).uids.detect { |e| passwd(f).uids.count(e) > 1 } do
      it { should be_nil }
    end
  end
end

control 'cis-dil-benchmark-6.2.17' do
  title 'Ensure no duplicate GIDs exist'
  desc  '
    Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to
    manually edit the /etc/group file and change the GID field.

    Rationale:
    User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.17'
  tag level: 1

  group_files.each do |f|
    describe etc_group(f).gids.detect { |e| etc_group(f).gids.count(e) > 1 } do
      it { should be_nil }
    end
  end
end

control 'cis-dil-benchmark-6.2.18' do
  title 'Ensure no duplicate user names exist'
  desc  '
    Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually
    edit the /etc/passwd file and change the user name.

    Rationale:
    If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd.
    For example, if "test4" has a UID of 1000 and a subsequent "test4" entry has a UID of 2000, logging in as "test4" will use UID 1000.
    Effectively, the UID is shared, which is a security problem.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.18'
  tag level: 1

  passwd_files.each do |f|
    describe passwd(f).users.detect { |e| passwd(f).users.count(e) > 1 } do
      it { should be_nil }
    end
  end
end

control 'cis-dil-benchmark-6.2.19' do
  title 'Ensure no duplicate group names exist'
  desc  '
    Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group
    file and change the group name.

    Rationale:
    If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group.
    Effectively, the GID is shared, which is a security problem.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.19'
  tag level: 1

  group_files.each do |f|
    describe etc_group(f).groups.detect { |e| etc_group(f).groups.count(e) > 1 } do
      it { should be_nil }
    end
  end
end

control 'cis-dil-benchmark-6.2.20' do
  title 'Ensure shadow group is empty'
  desc  '
    The shadow group allows system programs which require access the ability to read the /etc/shadow file. No users should be assigned
    to the shadow group.

    Rationale:
    Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers can gain read access
    to the /etc/shadow file, they can easily run a password cracking program against the hashed passwords to break them. Other security
    information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert additional user accounts.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:6.2.20'
  tag level: 1

  group_files.each do |f|
    describe etc_group(f).where(name: 'shadow') do
      its(:users) { should be_empty }
    end
  end
end
