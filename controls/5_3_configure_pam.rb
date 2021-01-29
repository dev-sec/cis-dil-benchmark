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

title '5.3 Configure PAM'

control 'cis-dil-benchmark-5.3.1' do # rubocop:disable Metrics/BlockLength
  title 'Ensure password creation requirements are configured'
  desc '
    The pam_cracklib.so module checks the strength of passwords. It performs
    checks such as making sure a password is not a dictionary word, it is a
    certain length, contains a mix of characters (e.g. alphabet, numeric, other)
    and more. The following are definitions of the pam_cracklib.so options.

    * try_first_pass - retrieve the password from a previous stacked PAM module.
      If not available, then prompt the user for a password.
    * retry=3 - Allow 3 tries before sending back a failure.
    * minlen=14 - password must be 14 characters or more
    * dcredit=-1 - provide at least one digit
    * ucredit=-1 - provide at least one uppercase character
    * ocredit=-1 - provide at least one special character
    * lcredit=-1 - provide at least one lowercase character

    The pam_pwquality.so module functions similarly but the minlen, dcredit,
    ucredit , ocredit , and lcredit parameters are stored in the
    /etc/security/pwquality.conf file. The settings shown above are one possible
    policy. Alter these values to conform to your own organization`s password
    policies.

    Rationale: Strong passwords protect systems from being hacked through brute
    force methods.
  '

  impact 1.0

  tag cis: 'distribution-independent-linux:5.3.1'
  tag level: 1

  if package('pam_cracklib').installed?
    describe.one do
      %w[common-password system-auth].each do |f|
        describe file("/etc/pam.d/#{f}") do
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*try_first_pass/) }
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*retry=[3210]/) }
        end
      end
    end

    describe.one do
      %w[common-password system-auth].each do |f|
        describe file("/etc/pam.d/#{f}") do
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*minlen=(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)/) }
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*dcredit=-[1-9][0-9]*\s*(?:#.*)?/) }
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*lcredit=-[1-9][0-9]*\s*(?:#.*)?/) }
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*ucredit=-[1-9][0-9]*\s*(?:#.*)?/) }
          its('content') { should match(/^password\s+required\s+pam_cracklib\.so (\S+\s+)*ocredit=-[1-9][0-9]*\s*(?:#.*)?/) }
        end
      end
    end
  end

  if package('pam_passwdqc').installed? || package('libpwquality').installed?
    describe.one do
      %w[common-password system-auth].each do |f|
        describe file("/etc/pam.d/#{f}") do
          its('content') { should match(/^password\s+requisite\s+pam_pwquality\.so (\S+\s+)*retry=[3210]/) }
          its('content') { should match(/^password\s+requisite\s+pam_pwquality\.so (\S+\s+)*try_first_pass/) }
        end
      end
    end

    describe file('/etc/security/pwquality.conf') do
      its('content') { should match(/^minlen = (1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\s*(?:#.*)?$/) }
      its('content') { should match(/^dcredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
      its('content') { should match(/^lcredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
      its('content') { should match(/^ucredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
      its('content') { should match(/^ocredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
    end
  end
end

control 'cis-dil-benchmark-5.3.2' do
  title 'Ensure lockout for failed password attempts is configured'
  desc  '
    Lock out users after n unsuccessful consecutive login attempts. The first
    sets of changes are made to the PAM configuration files. The second set of
    changes are applied to the program specific PAM configuration file. The
    second set of changes must be applied to each program that will lock out
    users. Check the documentation for each secondary program for instructions
    on how to configure them to work with PAM.
    Set the lockout number to the policy in effect at your site.

    Rationale: Locking out user IDs after n unsuccessful consecutive login
    attempts mitigates brute force password attacks against your systems.
  '

  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.2'
  tag level: 1

  describe 'cis-dil-benchmark-5.3.2' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-5.3.3' do
  title 'Ensure password reuse is limited'
  desc  '
    The /etc/security/opasswd file stores the users` old passwords and can be
    checked to ensure that users are not recycling recent passwords.

    Rationale: Forcing users not to reuse their past 5 passwords make it less
    likely that an attacker will be able to guess the password. Note that these
    change only apply to accounts configured on the local system.
  '

  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.3'
  tag level: 1

  describe.one do
    %w[common-password system-auth].each do |f|
      describe file("/etc/pam.d/#{f}") do
        its('content') { should match(/^password\s+(\S+\s+)+pam_unix\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
      end

      describe file("/etc/pam.d/#{f}") do
        its('content') { should match(/^password\s+(\S+\s+)+pam_pwhistory\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
      end
    end
  end
end

control 'cis-dil-benchmark-5.3.4' do
  title 'Ensure password hashing algorithm is SHA-512'
  desc  '
    The commands below change password encryption from md5 to sha512 (a much
    stronger hashing algorithm). All existing accounts will need to perform
    a password change to upgrade the stored hashes to the new algorithm.

    Rationale: The SHA-512 algorithm provides much stronger hashing than MD5,
    thus providing additional protection to the system by increasing the level
    of effort for an attacker to successfully determine passwords. Note that
    these change only apply to accounts configured on the local system.
  '

  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.4'
  tag level: 1

  describe.one do
    %w[common-password system-auth password-auth].each do |f|
      describe file("/etc/pam.d/#{f}") do
        its('content') { should match(/^password(\s+\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512/) }
      end
    end
  end
end
