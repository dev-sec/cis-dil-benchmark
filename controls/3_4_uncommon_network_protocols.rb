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

cis_level = attribute('cis_level')

title '3.4 Uncommon Network Protocols'

control 'cis-dil-benchmark-3.4.1' do
  title 'Ensure DCCP is disabled'
  desc  "The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.\n\nRationale: If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.1'
  tag level: 2

  only_if { cis_level == 2 }

  describe kernel_module('dccp') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-3.4.2' do
  title 'Ensure SCTP is disabled'
  desc  "The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.2'
  tag level: 2

  only_if { cis_level == 2 }

  describe kernel_module('sctp') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-3.4.3' do
  title 'Ensure RDS is disabled'
  desc  "The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.3'
  tag level: 2

  only_if { cis_level == 2 }

  describe kernel_module('rds') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-3.4.4' do
  title 'Ensure TIPC is disabled'
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.4.4'
  tag level: 2

  only_if { cis_level == 2 }

  describe kernel_module('tipc') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end
