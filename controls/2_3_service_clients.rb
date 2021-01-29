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

title '2.3 Service Clients'

control 'cis-dil-benchmark-2.3.1' do
  title 'Ensure NIS Client is not installed'
  desc  "The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.3.1'
  tag level: 1

  %w[nis ypbind].each do |p|
    describe package(p) do
      it { should_not be_installed }
    end
  end
end

control 'cis-dil-benchmark-2.3.2' do
  title 'Ensure rsh client is not installed'
  desc  "The rsh package contains the client commands for the rsh services.\n\nRationale: These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh, rcp and rlogin."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.3.2'
  tag level: 1

  %w[rsh-client rsh-redone-client rsh].each do |p|
    describe package(p) do
      it { should_not be_installed }
    end
  end
end

control 'cis-dil-benchmark-2.3.3' do
  title 'Ensure talk client is not installed'
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client, which allows initialization of talk sessions, is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.3.3'
  tag level: 1

  describe package('talk') do
    it { should_not be_installed }
  end
end

control 'cis-dil-benchmark-2.3.4' do
  title 'Ensure telnet client is not installed'
  desc  "The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.3.4'
  tag level: 1

  describe package('telnet') do
    it { should_not be_installed }
  end
end

control 'cis-dil-benchmark-2.3.5' do
  title 'Ensure LDAP client is not installed'
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.3.5'
  tag level: 1

  %w[ldap-utils openldap-clients openldap2-client].each do |p|
    describe package(p) do
      it { should_not be_installed }
    end
  end
end
