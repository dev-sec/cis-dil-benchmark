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

title '2.2 Special Purpose Services'

control 'cis-dil-benchmark-2.2.1.1' do
  title 'Ensure time synchronization is in use'
  desc  "System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.\n\nRationale: Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations."
  impact 0.0

  tag cis: 'distribution-independent-linux:2.2.1.1'
  tag level: 1

  describe.one do
    describe package('ntp') do
      it { should be_installed }
    end

    describe command('ntpd') do
      it { should exist }
    end

    describe package('chrony') do
      it { should be_installed }
    end

    describe command('chronyd') do
      it { should exist }
    end
  end
end

control 'cis-dil-benchmark-2.2.1.2' do
  title 'Ensure ntp is configured'
  desc "ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on NTP can be found at http://www.ntp.org. ntp can be configured to be a client and/or a server.\nThis recommendation only applies if ntp is in use on the system.\n\nRationale: If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.1.2'
  tag level: 1

  only_if do
    package('ntp').installed? || command('ntpd').exist?
  end

  describe.one do
    describe ntp_conf do
      its(:server) { should_not eq nil }
    end

    describe ntp_conf do
      its(:pool) { should_not eq nil }
    end
  end

  describe ntp_conf.restrict.to_s do
    it { should match(/default\s+(\S+\s+)*kod(?:\s+|\s?")/) }
    it { should match(/default\s+(\S+\s+)*nomodify(?:\s+|\s?")/) }
    it { should match(/default\s+(\S+\s+)*notrap(?:\s+|\s?")/) }
    it { should match(/default\s+(\S+\s+)*nopeer(?:\s+|\s?")/) }
    it { should match(/default\s+(\S+\s+)*noquery(?:\s+|\s?")/) }
  end

  describe.one do
    describe file('/etc/init.d/ntp') do
      its(:content) { should match(/^RUNASUSER=ntp\s*(?:#.*)?$/) }
    end

    describe file('/etc/init.d/ntpd') do
      its(:content) { should match(/daemon\s+(\S+\s+)-u ntp:ntp(?:\s+|\s?")/) }
    end

    describe file('/etc/sysconfig/ntpd') do
      its(:content) { should match(/^OPTIONS="(?:.)?-u ntp:ntp\s*(?:.)?"\s*(?:#.*)?$/) }
    end

    describe file('/usr/lib/systemd/system/ntpd.service') do
      its(:content) { should match(%r{^ExecStart=/usr/s?bin/ntpd (?:.)?-u ntp:ntp\s*(?:.)?$}) }
    end
  end
end

control 'cis-dil-benchmark-2.2.1.3' do
  title 'Ensure chrony is configured'
  desc  "chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server.\n\nRationale: If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.\nThis recommendation only applies if chrony is in use on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.1.3'
  tag level: 1

  only_if do
    package('chrony').installed? || command('chronyd').exist?
  end

  describe.one do
    %w[/etc/chrony/chrony.conf /etc/chrony.conf].each do |f|
      describe file(f) do
        its('content') { should match(/^(pool|server)\s+\S+/) }
      end
    end
  end

  describe processes('chronyd') do
    its(:users) { should cmp 'chrony' }
  end
end

control 'cis-dil-benchmark-2.2.1.4' do
  title 'Ensure systemd-timesyncd is configured'
  desc  "systemd-timesyncd is a daemon that has been added for synchronizing the system clock across the network. It implements an SNTP client. In contrast to NTP implementations such as chrony or the NTP reference server this only implements a client side, and does not bother with the full NTP complexity, focusing only on querying time from one remote server and synchronizing the local clock to it. The daemon runs with minimal privileges, and has been hooked up with networkd to only operate when network connectivity is available. The daemon saves the current clock to disk every time a new NTP sync has been acquired, and uses this to possibly correct the system clock early at bootup, in order to accommodate for systems that lack an RTC such as the Raspberry Pi and embedded devices, and make sure that time monotonically progresses on these systems, even if it is not always correct. To make use of this daemon a new system user and group 'systemd- timesync' needs to be created on installation of systemd. This recommendation only applies if timesyncd is in use on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.1.4'
  tag level: 1

  only_if do
    service('systemd-timesyncd.service').enabled?
  end

  describe file('/etc/systemd/timesyncd.conf') do
    its('content') { should match /^NTP=\S+/ }
    its('content') { should match /^FallbackNTP=\S+/ }
    its('content') { should match /^RootDistanceMaxSec=[0-9]/ }
  end
end

control 'cis-dil-benchmark-2.2.2' do
  title 'Ensure X Window System is not installed'
  desc  "The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.\n\nRationale: Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.2'
  tag level: 1

  describe packages(/^xserver-xorg.*/) do
    its(:names) { should be_empty }
  end

  describe packages(/^xorg-x11-server.*/) do
    its(:names) { should be_empty }
  end
end

control 'cis-dil-benchmark-2.2.3' do
  title 'Ensure Avahi Server is not enabled'
  desc  "Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.\n\nRationale: Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attach surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.3'
  tag level: 1

  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'cis-dil-benchmark-2.2.4' do
  title 'Ensure CUPS is not enabled'
  desc  "The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.\n\nRationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.4'
  tag level: 1

  describe service('cups') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'cis-dil-benchmark-2.2.5' do
  title 'Ensure DHCP Server is not enabled'
  desc  "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.\n\nRationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.5'
  tag level: 1

  %w[isc-dhcp-server isc-dhcp-server6 dhcpd].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.6' do
  title 'Ensure LDAP server is not enabled'
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP server, it is recommended that the software be disabled to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.6'
  tag level: 1

  describe service('slapd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'cis-dil-benchmark-2.2.7' do
  title 'Ensure NFS and RPC are not enabled'
  desc  "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.\n\nRationale: If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.7'
  tag level: 1

  %w[nfs-kernel-server nfs rpcbind].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.8' do
  title 'Ensure DNS Server is not enabled'
  desc  "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.\n\nRationale: Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.8'
  tag level: 1

  %w[named bind bind9].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.9' do
  title 'Ensure FTP Server is not enabled'
  desc  "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.\n\nRationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.9'
  tag level: 1

  describe service('vsftpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'cis-dil-benchmark-2.2.10' do
  title 'Ensure HTTP server is not enabled'
  desc  "HTTP or web servers provide the ability to host web site content.\n\nRationale: Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.10'
  tag level: 1

  %w[apache apache2 httpd lighttpd nginx].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.11' do
  title 'Ensure IMAP and POP3 server is not enabled'
  desc  "dovecot is an open source IMAP and POP3 server for Linux based systems.\n\nRationale: Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the service be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.11'
  tag level: 1

  %w[dovecot courier-imap cyrus-imap].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.12' do
  title 'Ensure Samba is not enabled'
  desc  "The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.\n\nRationale: If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.12'
  tag level: 1

  %w[samba smb smbd].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.13' do
  title 'Ensure HTTP Proxy Server is not enabled'
  desc  "Squid is a standard proxy server used in many distributions and environments.\n\nRationale: If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.13'
  tag level: 1

  %w[squid squid3].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.14' do
  title 'Ensure SNMP Server is not enabled'
  desc  "The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.\n\nRationale: The SNMP server communicates using SNMP v1, which transmits data in the clear and does not require authentication to execute commands. Unless absolutely necessary, it is recommended that the SNMP service not be used."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.14'
  tag level: 1

  describe service('snmpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'cis-dil-benchmark-2.2.15' do
  title 'Ensure mail transfer agent is configured for local-only mode'
  desc  "Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.\n\nRationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.15'
  tag level: 1

  describe port(25).where { address !~ /^(127\.0\.0\.1|::1)$/ } do
    its(:entries) { should be_empty }
  end
end

control 'cis-dil-benchmark-2.2.16' do
  title 'Ensure rsync service is not enabled'
  desc  "The rsyncd service can be used to synchronize files between systems over network links.\n\nRationale: The rsyncd service presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.16'
  tag level: 1

  %w[rsync rsyncd].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-2.2.17' do
  title 'Ensure NIS Server is not enabled'
  desc  "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used"
  impact 1.0

  tag cis: 'distribution-independent-linux:2.2.17'
  tag level: 1

  %w[nis ypserv].each do |s|
    describe service(s) do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end
