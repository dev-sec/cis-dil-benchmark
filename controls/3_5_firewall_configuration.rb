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

title '3.5 Firewall Configuration'

control 'cis-dil-benchmark-3.5.1.1' do
  title 'Ensure IPv6 default deny firewall policy'
  desc  "A default deny all policy on connections ensures that any unconfigured network usage will be rejected.\n\nRationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.1.1'
  tag level: 1

  %w(INPUT OUTPUT FORWARD).each do |chain|
    describe.one do
      describe ip6tables do
        it { should have_rule("-P #{chain} DROP") }
      end
      describe ip6tables do
        it { should have_rule("-P #{chain} REJECT") }
      end
    end
  end
end

control 'cis-dil-benchmark-3.5.1.2' do
  title 'Ensure IPv6 loopback traffic is configured'
  desc  "Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (::1).\n\nRationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (::1) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.1.2'
  tag level: 1

  describe iptables do
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
    it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
    it { should have_rule('-A INPUT -s ::1 -j DROP') }
  end
end

control 'cis-dil-benchmark-3.5.1.3' do
  title 'Ensure IPv6 outbound and established connections are configured'
  desc  "Configure the firewall rules for new outbound, and established IPv6 connections.\n\nRationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.5.1.3'
  tag level: 1

  %w(tcp udp icmp).each do |proto|
    describe.one do
      describe ip6tables do
        it { should have_rule("-A OUTPUT -p #{proto} -m state --state NEW,ESTABLISHED -j ACCEPT") }
        it { should have_rule("-A INPUT -p #{proto} -m state --state ESTABLISHED -j ACCEPT") }
      end
      describe ip6tables do
        it { should have_rule("-A OUTPUT -p #{proto} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT") }
        it { should have_rule("-A INPUT -p #{proto} -m conntrack --ctstate ESTABLISHED -j ACCEPT") }
      end
    end
  end
end

control 'cis-dil-benchmark-3.5.1.4' do
  title 'Ensure IPv6 firewall rules exist for all open ports'
  desc  "Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.\n\nRationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.5.1.4'
  tag level: 1

  port.where { address !~ /^::1$/ }.ports.each do |port|
    describe "Firewall rule should exist for port #{port}" do
      subject { iptables.retrieve_rules.any? { |s| s =~ /\s+--dport #{port}\s+/ } }
      it { should be true }
    end
  end
end

control 'cis-dil-benchmark-3.5.2.1' do
  title 'Ensure default deny firewall policy'
  desc  "A default deny all policy on connections ensures that any unconfigured network usage will be rejected.\n\nRationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.2.1'
  tag level: 1

  %w(INPUT OUTPUT FORWARD).each do |chain|
    describe.one do
      describe iptables do
        it { should have_rule("-P #{chain} DROP") }
      end
      describe iptables do
        it { should have_rule("-P #{chain} REJECT") }
      end
    end
  end
end

control 'cis-dil-benchmark-3.5.2.2' do
  title 'Ensure loopback traffic is configured'
  desc  "Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8).\n\nRationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.2.2'
  tag level: 1

  describe iptables do
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
    it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
    it { should have_rule('-A INPUT -s 127.0.0.0/8 -j DROP') }
  end
end

control 'cis-dil-benchmark-3.5.2.3' do
  title 'Ensure outbound and established connections are configured'
  desc  "Configure the firewall rules for new outbound, and established connections.\n\nRationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.5.2.3'
  tag level: 1

  %w(tcp udp icmp).each do |proto|
    describe.one do
      describe iptables do
        it { should have_rule("-A OUTPUT -p #{proto} -m state --state NEW,ESTABLISHED -j ACCEPT") }
        it { should have_rule("-A INPUT -p #{proto} -m state --state ESTABLISHED -j ACCEPT") }
      end
      describe iptables do
        it { should have_rule("-A OUTPUT -p #{proto} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT") }
        it { should have_rule("-A INPUT -p #{proto} -m conntrack --ctstate ESTABLISHED -j ACCEPT") }
      end
    end
  end
end

control 'cis-dil-benchmark-3.5.2.4' do
  title 'Ensure firewall rules exist for all open ports'
  desc  "Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.\n\nRationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.2.4'
  tag level: 1

  port.where { address !~ /^127\.0\.0\.1$/ }.ports.each do |port|
    describe "Firewall rule should exist for port #{port}" do
      subject { iptables.retrieve_rules.any? { |s| s =~ /\s+--dport #{port}\s+/ } }
      it { should be true }
    end
  end
end

control 'cis-dil-benchmark-3.5.3' do
  title 'Ensure iptables is installed'
  desc  "iptables allows configuration of the IPv4 and IPv6 tables in the linux kernel and the rules stored within them. Most firewall configuration utilities operate as a front end to iptables.\n\nRationale: iptables is required for firewall management and configuration."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.5.3'
  tag level: 1

  describe package('iptables') do
    it { should be_installed }
  end
end