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

title '1.7 Warning Banners'

control 'cis-dil-benchmark-1.7.1.1' do
  title 'Ensure message of the day is configured properly'
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \n\\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.1.1'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/motd') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.2' do
  title 'Ensure local login warning banner is configured properly'
  desc "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(9) supports the following options, they display operating system information: \\m - machine architecture ( uname -m ) \\r - operating system release ( uname -r ) \\s - operating system name \\v - operating system version ( uname -v )\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.2'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/issue') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.3' do
  title 'Ensure remote login warning banner is configured properly'
  desc "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture ( uname -m ) \\r - operating system release ( uname -r ) \\s - operating system name \\v - operating system version ( uname -v )\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.3'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/issue.net') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.4' do
  title 'Ensure permissions on /etc/motd are configured'
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n\nRationale: If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.4'
  tag level: 1

  describe file('/etc/motd') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.1.5' do
  title 'Ensure permissions on /etc/issue are configured'
  desc  "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\n\nRationale: If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.1.5'
  tag level: 1

  describe file('/etc/issue') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.1.6' do
  title 'Ensure permissions on /etc/issue.net are configured'
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n\nRationale: If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.6'
  tag level: 1

  describe file('/etc/issue.net') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.2' do
  title 'Ensure GDM login banner is configured'
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.2'
  tag level: 1

  only_if do
    package('gdm').installed?
  end

  describe file('/etc/dconf/profile/gdm') do
    its(:content) { should match(/^user-db:user$/) }
    its(:content) { should match(/^system-db:gdm$/) }
    its(:content) { should match(%r{^file-db:/usr/share/gdm/greeter-dconf-defaults$}) }
  end

  describe file('/etc/dconf/db/gdm.d/01-banner-message') do
    its(:content) { should match(/^banner-message-enable=true$/) }
    its(:content) { should match(/^banner-message-text='.+'$/) }
  end
end
