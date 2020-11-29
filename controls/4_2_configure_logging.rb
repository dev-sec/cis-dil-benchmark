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
#

title '4.2 Configure Logging'

control 'cis-dil-benchmark-4.2.1.1' do
  title 'Ensure rsyslog is installed'
  desc  "The rsyslog software is a recommended replacement to the original syslogd daemon which provide improvements over syslogd, such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server.\n\nRationale: The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.1.1'
  tag level: 1

  describe service('rsyslog') do
    it { should be_installed }
  end
end

control 'cis-dil-benchmark-4.2.1.2' do
  title 'Ensure rsyslog Service is enabled'
  desc  "Once the rsyslog package is installed it needs to be activated.\n\nRationale: If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.1.2'
  tag level: 1

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

control 'cis-dil-benchmark-4.2.1.3' do
  title 'Ensure logging is configured'
  desc  "The /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files specifies rules for logging and which files are to be used to log certain classes of messages.\n\nRationale: A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.)."
  impact 0.0

  tag cis: 'distribution-independent-linux:4.2.1.3'
  tag level: 1

  describe file('/etc/rsyslog.conf') do
    it { should exist }
  end
end

control 'cis-dil-benchmark-4.2.1.4' do
  title 'Ensure rsyslog default file permissions configured'
  desc  "rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.\n\nRationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.1.4'
  tag level: 1

  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/^\$FileCreateMode\s+0[6420][40]0\s*(?:#.*)?$/) }
  end
end

control 'cis-dil-benchmark-4.2.1.5' do
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  desc  "The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead.\n\nRationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system"
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.1.5'
  tag level: 1

  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/^\s*\*\.\*\s+@/) }
  end
end

control 'cis-dil-benchmark-4.2.1.6' do
  title 'Ensure remote rsyslog messages are only accepted on designated log hosts.'
  desc  "By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.\n\nRationale: The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location."
  impact 0.0

  tag cis: 'distribution-independent-linux:4.2.1.6'
  tag level: 1

  describe command("grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf") do
    its('stdout') { should_not match /^\s*$ModLoad imtcp/ }
  end
  describe command("grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf") do
    its('stdout') { should_not match /^\s*$InputTCPServerRun/ }
  end
end

control 'cis-dil-benchmark-4.2.2.1' do
  title 'Ensure journald is configured to send logs to rsyslog'
  desc  "Data from journald may be stored in volatile memory or persisted locally on the server. Utilities exist to accept remote export of journald logs, however, use of the rsyslog service provides a consistent means of log collection and export.\n\nRationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.2.1'
  tag level: 1

  describe file('/etc/systemd/journald.conf') do
    its('contents') { should match(/^ForwardToSyslog=yes$/) }
  end
end

control 'cis-dil-benchmark-4.2.2.2' do
  title 'Ensure journald is configured to compress large log file'
  desc  "The journald system includes the capability of compressing overly large files to avoid filling up the system with logs or making the logs unmanageably large.\n\nRationale: Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability. Compressing logs prior to write can prevent sudden, unexpected filesystem impacts."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.2.2'
  tag level: 1

  describe file('/etc/systemd/journald.conf') do
    its('contents') { should match(/^Compress=yes$/) }
  end
end

control 'cis-dil-benchmark-4.2.2.3' do
  title 'Ensure journald is configured to write logfiles to persistent disk'
  desc  "Data from journald may be stored in volatile memory or persisted locally on the server. Logs in memory will be lost upon a system reboot. By persisting logs to local disk on the server they are protected from loss.\n\nRationale: Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted the operations or security of a system even after a system crash or reboot."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.2.3'
  tag level: 1

  describe file('/etc/systemd/journald.conf') do
    its('contents') { should match(/^Storage=persistent$/) }
  end
end

control 'cis-dil-benchmark-4.2.3' do
  title 'Ensure permissions on all logfiles are configured'
  desc  "Log files stored in /var/log/ contain logged information from many services on the system, or on log hosts others as well.\n\nRationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected."
  impact 1.0

  tag cis: 'distribution-independent-linux:4.2.3'
  tag level: 1

  group_write_excepts = %w[lastlog wtmp]
  command('find /var/log -type f').stdout.split.each do |f|
    describe file(f) do
      it { should_not be_writable.by 'group' } unless group_write_excepts.include?(f.split('/')[-1])
      it { should_not be_executable.by 'group' }
      it { should_not be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
    end
  end
end
