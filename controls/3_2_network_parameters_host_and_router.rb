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

title '3.2 Network Parameters (Host and Router)'

control 'cis-dil-benchmark-3.2.1' do
  title 'Ensure source routed packets are not accepted'
  desc  "In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.\n\nRationale: Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.1'
  tag level: 1

  %w[
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.default.accept_source_route
    net.ipv6.conf.all.accept_source_route
    net.ipv6.conf.default.accept_source_route
  ].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end

control 'cis-dil-benchmark-3.2.2' do
  title 'Ensure ICMP redirects are not accepted'
  desc  "ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.\n\nRationale: Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.2'
  tag level: 1

  %w[
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.default.accept_redirects
  ].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end

control 'cis-dil-benchmark-3.2.3' do
  title 'Ensure secure ICMP redirects are not accepted'
  desc  "Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.\n\nRationale: It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.3'
  tag level: 1

  %w[net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end

control 'cis-dil-benchmark-3.2.4' do
  title 'Ensure suspicious packets are logged'
  desc  "When enabled, this feature logs packets with un-routable source addresses to the kernel log.\n\nRationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.4'
  tag level: 1

  %w[net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 1 }
    end
  end
end

control 'cis-dil-benchmark-3.2.5' do
  title 'Ensure broadcast ICMP requests are ignored'
  desc  "Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.\n\nRationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.5'
  tag level: 1

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its(:value) { should_not be_nil }
    its(:value) { should eq 1 }
  end
end

control 'cis-dil-benchmark-3.2.6' do
  title 'Ensure bogus ICMP responses are ignored'
  desc  "Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.\n\nRationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.6'
  tag level: 1

  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its(:value) { should_not be_nil }
    its(:value) { should eq 1 }
  end
end

control 'cis-dil-benchmark-3.2.7' do
  title 'Ensure Reverse Path Filtering is enabled'
  desc  "Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding source packet came from, the packet is dropped (and logged if log_martians is set).\n\nRationale: Setting these flags is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.7'
  tag level: 1

  %w[net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 1 }
    end
  end
end

control 'cis-dil-benchmark-3.2.8' do
  title 'Ensure TCP SYN Cookies is enabled'
  desc  "When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the system to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.\n\nRationale: Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.8'
  tag level: 1

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its(:value) { should_not be_nil }
    its(:value) { should eq 1 }
  end
end

control 'cis-dil-benchmark-3.2.9' do
  title 'Ensure IPv6 router advertisements are not accepted'
  desc  "This setting disables the system's ability to accept IPv6 router advertisements.\n\nRationale: It is recommended that systems do not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.2.9'
  tag level: 1

  %w[net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra].each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end
