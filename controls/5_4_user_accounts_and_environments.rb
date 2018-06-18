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

title '5.4 User Accounts and Environments'

shadow_files = ['/etc/shadow']
shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

passwd_files = ['/etc/passwd']
passwd_files << '/usr/share/baselayout/passwd' if file('/etc/nsswitch.conf').content =~ /^passwd:\s+(\S+\s+)*usrfiles/

control 'cis-dil-benchmark-5.4.1.1' do
  title 'Ensure password expiration is 90 days or less'
  desc  "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days.\n\nRationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.1.1'
  tag level: 1

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 90 }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.password && %w(* !)).any?

      describe user do
        its(:max_days) { should cmp <= 90 }
      end
    end
  end
end

control 'cis-dil-benchmark-5.4.1.2' do
  title 'Ensure minimum days between password changes is 7 or more'
  desc  "The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.\n\nRationale: By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.1.2'
  tag level: 1

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 7 }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.password && %w(* !)).any?

      describe user do
        its(:min_days) { should cmp >= 7 }
      end
    end
  end
end

control 'cis-dil-benchmark-5.4.1.3' do
  title 'Ensure password expiration warning days is 7 or more'
  desc  "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days.\n\nRationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.1.3'
  tag level: 1

  describe login_defs do
    its('PASS_WARN_AGE') { should cmp >= 7 }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.password && %w(* !)).any?

      describe user do
        its(:warn_days) { should cmp >= 7 }
      end
    end
  end
end

control 'cis-dil-benchmark-5.4.1.4' do
  title 'Ensure inactive password lock is 30 days or less'
  desc  "User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 30 days after password expiration be disabled.\n\nRationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.1.4'
  tag level: 1

  describe command('useradd -D') do
    its(:stdout) { should match(/^INACTIVE=(30|[1-2][0-9]|[1-9])$/) }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.password && %w(* !)).any?

      describe user do
        its(:inactive_days) { should cmp <= 30 }
      end
    end
  end
end

control 'cis-dil-benchmark-5.4.2' do
  title 'Ensure system accounts are non-login'
  desc  "There are a number of accounts provided with Ubuntu that are used to manage applications and are not intended to provide an interactive shell.\n\nRationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, Ubuntu sets the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin. This prevents the account from potentially being used to run any commands."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.2'
  tag level: 1

  uid_min = login_defs.UID_MIN.to_i

  passwd_files.each do |f|
    passwd(f).where { uid.to_i < uid_min }.entries.each do |user|
      next if %w(root sync shutdown halt).include? user.user

      describe user do
        its(:shell) { should match(%r{(/usr/sbin/nologin|/sbin/nologin|/bin/false)}) }
      end

      describe shadow(users.user) do
        its(:password) { should be_all { |m| m == '*' } }
      end
    end
  end
end

control 'cis-dil-benchmark-5.4.3' do
  title 'Ensure default group for the root account is GID 0'
  desc  "The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user.\n\nRationale: Using GID 0 for the  root account helps prevent  root -owned files from accidentally becoming accessible to non-privileged users."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.3'
  tag level: 1

  describe passwd.users('root') do
    its(:gids) { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.4.4' do
  title 'Ensure default user umask is 027 or more restrictive'
  desc  "The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files (.profile, .bashrc, etc.) in their home directories.\n\nRationale: Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.4'
  tag level: 1

  %w(bash.bashrc profile bashrc).each do |f|
    describe file("/etc/#{f}") do
      its(:content) { should_not match(/^umask [01234567](0[7654321]|[7654321][654321])\s*(?:#.*)?$/) }
    end
  end

  describe.one do
    %w(bash.bashrc profile bashrc).each do |f|
      next unless file("/etc/#{f}").file?
      describe file("/etc/#{f}") do
        its(:content) { should match(/^umask [01234567][2367]7\s*(?:#.*)?$/) }
      end
    end
  end
end

control 'cis-dil-benchmark-5.5' do
  title 'Ensure root login is restricted to system console'
  desc  "The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.\n\nRationale: Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined."
  impact 0.0

  tag cis: 'distribution-independent-linux:5.5'
  tag level: 1

  describe 'cis-dil-benchmark-5.5' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-5.6' do
  title 'Ensure access to the su command is restricted'
  desc  "The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su.\n\nRationale: Restricting the use of su, and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo, whereas su can only record that a user executed the su program."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.6'
  tag level: 1

  describe file('/etc/pam.d/su') do
    its(:content) { should match(/^auth\s+required\s+pam_wheel.so use_uid$/) }
  end
end
