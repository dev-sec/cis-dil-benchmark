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

title '3.4 TCP Wrappers'

control 'cis-dil-benchmark-3.4.1' do
  title 'Ensure TCP Wrappers is installed'
  desc  "TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it.\n\nRationale: TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. It is recommended that all services that can support TCP Wrappers, use it."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.1'
  tag level: 1

  describe.one do
    %w(tcpd tcp_wrappers).each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end
  end
end

control 'cis-dil-benchmark-3.4.2' do
  title 'Ensure /etc/hosts.allow is configured'
  desc  "The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file.\n\nRationale: The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.2'
  tag level: 1

  describe file('/etc/hosts.allow') do
    it { should exist }
  end
end

control 'cis-dil-benchmark-3.4.3' do
  title 'Ensure /etc/hosts.deny is configured'
  desc  "The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file.\n\nRationale: The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.3'
  tag level: 1

  describe file('/etc/hosts.deny') do
    its(:content) { should match(/^ALL: ALL/) }
  end
end

control 'cis-dil-benchmark-3.4.4' do
  title 'Ensure permissions on /etc/hosts.allow are configured'
  desc  "The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.4'
  tag level: 1

  describe file('/etc/hosts.allow') do
    it { should exist }
    it { should be_readable.by 'owner' }
    it { should be_writable.by 'owner' }
    it { should_not be_executable.by 'owner' }
    it { should be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its(:uid) { should cmp 0 }
    its(:gid) { should cmp 0 }
    its(:sticky) { should equal false }
    its(:suid) { should equal false }
    its(:sgid) { should equal false }
  end
end

control 'cis-dil-benchmark-3.4.5' do
  title 'Ensure permissions on /etc/hosts.deny are 644'
  desc  "The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.deny file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.5'
  tag level: 1

  describe file('/etc/hosts.deny') do
    it { should exist }
    it { should be_readable.by 'owner' }
    it { should be_writable.by 'owner' }
    it { should_not be_executable.by 'owner' }
    it { should be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its(:uid) { should cmp 0 }
    its(:gid) { should cmp 0 }
    its(:sticky) { should equal false }
    its(:suid) { should equal false }
    its(:sgid) { should equal false }
  end
end
