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

title '2.1 inetd Services'

control 'cis-dil-benchmark-2.1.1' do
  title 'Ensure chargen services are not enabled'
  desc  "chargen is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.1'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('chargen') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:chargen) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:chargen) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.2' do
  title 'Ensure daytime services are not enabled'
  desc  "daytime is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.2'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('daytime') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:daytime) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:daytime) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.3' do
  title 'Ensure discard services are not enabled'
  desc  "discard is a network service that simply discards all data it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.3'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('discard') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:discard) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:discard) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.4' do
  title 'Ensure echo services are not enabled'
  desc  "echo is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.4'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('echo') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:echo) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:echo) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.5' do
  title 'Ensure time services are not enabled'
  desc  "time is a network service that responds with the server's current date and time as a 32 bit integer. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.5'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('time') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:time) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:time) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.6' do
  title 'Ensure rsh server is not enabled'
  desc  "The Berkeley rsh-server (rsh, rlogin, rexec) package contains legacy services that exchange credentials in clear-text.\n\nRationale: These legacy services contain numerous security exposures and have been replaced with the more secure SSH package."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.6'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  %w[shell login exec rsh rlogin rexec].each do |s|
    describe xinetd_conf.services(s) do
      it { should be_disabled }
    end

    describe inetd_conf do
      its(s) { should eq nil }
    end

    command('find /etc/inetd.d -type f').stdout.split.each do |entry|
      describe inetd_conf(entry) do
        its(s) { should eq nil }
      end
    end
  end
end

control 'cis-dil-benchmark-2.1.7' do
  title 'Ensure talk server is not enabled'
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.7'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  %w[talk ntalk].each do |s|
    describe xinetd_conf.services(s) do
      it { should be_disabled }
    end

    describe inetd_conf do
      its(s) { should eq nil }
    end

    command('find /etc/inetd.d -type f').stdout.split.each do |entry|
      describe inetd_conf(entry) do
        its(s) { should eq nil }
      end
    end
  end
end

control 'cis-dil-benchmark-2.1.8' do
  title 'Ensure telnet server is not enabled'
  desc  "The telnet-server package contains the telnet daemon, which accepts connections from users from other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.8'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('telnet') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:telnet) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:telnet) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.9' do
  title 'Ensure tftp server is not enabled'
  desc  "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The packages tftp and atftp are both used to define and support a TFTP server.\n\nRationale: TFTP does not support authentication nor does it ensure the confidentiality or integrity of data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In that case, extreme caution must be used when configuring the services."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.9'
  tag level: 1

  only_if('inetd/xinetd config exists') do
    file('/etc/xinetd.conf').exist? || file('/etc/inetd.conf').exist?
  end

  describe xinetd_conf.services('tftp') do
    it { should be_disabled }
  end

  describe inetd_conf do
    its(:tftp) { should eq nil }
  end

  command('find /etc/inetd.d -type f').stdout.split.each do |entry|
    describe inetd_conf(entry) do
      its(:tftp) { should eq nil }
    end
  end
end

control 'cis-dil-benchmark-2.1.10' do
  title 'Ensure xinetd is not enabled'
  desc  "The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.\n\nRationale: If there are no xinetd services required, it is recommended that the daemon be disabled."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.1.10'
  tag level: 1

  describe service('xinetd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
