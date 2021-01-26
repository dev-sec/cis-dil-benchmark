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

title '3.3 TCP Wrappers'

control 'cis-dil-benchmark-3.3.1' do
  title 'Ensure TCP Wrappers is installed'
  desc '
    Many Linux distributions provide value-added firewall solutions which provide easy, advanced management of network traffic into and out
    of the local system. When these solutions are available and appropriate for an environment they should be used.

    In cases where a value-added firewall is not provided by a distribution, TCP Wrappers provides a simple access
    list and standardized logging method for services capable of supporting it. Services that are called from `inetd` and `xinetd` support the use
    of TCP wrappers. Any service that can support TCP wrappers will have the `libwrap.so` library attached to it.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.1'
  tag level: 1

  describe.one do
    %w[tcpd tcp_wrappers].each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end
  end
end

control 'cis-dil-benchmark-3.3.2' do
  title 'Ensure /etc/hosts.allow is configured'
  desc '
    The `/etc/hosts.allow` file specifies which IP addresses are permitted to connect
    to the host. It is intended to be used in conjunction with the `/etc/hosts.deny` file.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.2'
  tag level: 1

  describe file('/etc/hosts.allow') do
    it { should exist }
  end
end

control 'cis-dil-benchmark-3.3.3' do
  title 'Ensure /etc/hosts.deny is configured'
  desc '
    The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host.
    It is intended to be used in conjunction with the /etc/hosts.allow file.

    Rationale: The /etc/hosts.deny file serves as a failsafe so that any host not specified
    in /etc/hosts.allow is denied access to the system.
  '
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.3'
  tag level: 1

  describe file('/etc/hosts.deny') do
    its('content') { should match(/^ALL: ALL/) }
  end
end

control 'cis-dil-benchmark-3.3.4' do
  title 'Ensure permissions on /etc/hosts.allow are configured'
  desc '
    The /etc/hosts.allow file contains networking information that is used by many applications and
    therefore must be readable for these applications to operate.

    Rationale: It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default,
    the file permissions could be changed either inadvertently or through malicious actions.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:3.3.4'
  tag level: 1

  describe file('/etc/hosts.allow') do
    it { should exist }
    it { should be_file }

    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }

    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-3.3.5' do
  title 'Ensure permissions on /etc/hosts.deny are configured'
  desc '
    The `/etc/hosts.deny` file contains network information that is used by many system applications and therefore
    must be readable for these applications to operate.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:3.3.5'
  tag level: 1

  describe file('/etc/hosts.deny') do
    it { should exist }
    it { should be_file }

    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }

    its('mode') { should cmp '0644' }
  end
end
