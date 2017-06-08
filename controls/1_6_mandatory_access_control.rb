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

title '1.6 Mandatory Access Control'

control 'cis-dil-benchmark-1.6.1.1' do
  title 'Ensure SELinux is not disabled in bootloader configuration'
  desc  "Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.\n\nRationale: SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.1'
  tag level: 2

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  describe.one do
    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      describe file(f) do
        its(:content) { should_not match(/selinux=0/) }
        its(:content) { should_not match(/enforcing=0/) }
      end
    end
  end
end

control 'cis-dil-benchmark-1.6.1.2' do
  title 'Ensure the SELinux state is enforcing'
  desc  "Set SELinux to enable when the system is booted.\n\nRationale: SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.2'
  tag level: 1

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  describe file('/etc/selinux/config') do
    its(:content) { should match(/^SELINUX=enforcing\s*(?:#.*)?$/) }
  end

  describe command('sestatus') do
    its(:stdout) { should match(/SELinux status:\s+enabled/) }
    its(:stdout) { should match(/Current mode:\s+enforcing/) }
    its(:stdout) { should match(/Mode from config file:\s+enforcing/) }
  end
end

control 'cis-dil-benchmark-1.6.1.3' do
  title 'Ensure SELinux policy is configured'
  desc  "Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.3'
  tag level: 2

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  describe file('/etc/selinux/config') do
    its(:content) { should match(/^SELINUXTYPE=(targeted|mls)\s*(?:#.*)?$/) }
  end

  describe command('sestatus') do
    its(:stdout) { should match(/Policy from config file:\s+(targeted|mls)/) }
  end
end

control 'cis-dil-benchmark-1.6.1.4' do
  title 'Ensure SETroubleshoot is not installed'
  desc  "The SETroubleshoot service notifies desktop users of SELinux denials through a user- friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.\n\nRationale: The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.4'
  tag level: 2

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  describe package('setroubleshoot') do
    it { should_not be_installed }
  end

  describe command('setroubleshoot') do
    it { should_not exist }
  end
end

control 'cis-dil-benchmark-1.6.1.5' do
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  desc "The mcstransd daemon provides category label information to client processes requesting information. The label translations are defined in /etc/selinux/targeted/setrans.conf\n\nRationale: Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.5'
  tag level: 2

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  describe package('mcstrans') do
    it { should_not be_installed }
  end

  describe command('mcstransd') do
    it { should_not exist }
  end
end

control 'cis-dil-benchmark-1.6.1.6' do
  title 'Ensure no unconfined daemons exist'
  desc  "Daemons that are not defined in SELinux policy will inherit the security context of their parent process.\n\nRationale: Since daemons are launched and descend from the init process, they will inherit the security context label initrc_t. This could cause the unintended consequence of giving the process more permission than it requires."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.6'
  tag level: 2

  only_if do
    package('selinux').installed? || command('sestatus').exist?
  end

  processes(/.*/).where { pid > 0 }.entries.each do |p|
    describe p.label.to_s.split(':')[2] do
      it { should_not cmp 'initrc_t' }
    end
  end
end

control 'cis-dil-benchmark-1.6.2.1' do
  title 'Ensure AppArmor is not disabled in bootloader configuration'
  desc  "Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters.\n\nRationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.1'
  tag level: 1

  only_if do
    package('apparmor').installed?
  end

  describe.one do
    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      describe file(f) do
        its(:content) { should_not match(/apparmor=0/) }
      end
    end
  end
end

control 'cis-dil-benchmark-1.6.2.2' do
  title 'Ensure all AppArmor Profiles are enforcing'
  desc  "AppArmor profiles define what resources applications are able to access.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.2'
  tag level: 1

  only_if do
    package('apparmor').installed?
  end

  describe command('apparmor_status --profiled') do
    its(:stdout) { should cmp > 0 }
  end

  describe command('apparmor_status --complaining') do
    its(:stdout) { should cmp.zero? }
  end

  describe command('apparmor_status') do
    its(:stdout) { should match(/0 processes are unconfined/) }
  end
end

control 'cis-dil-benchmark-1.6.3' do
  title 'Ensure SELinux or AppArmor are installed'
  desc  "SELinux and AppArmor provide Mandatory Access Controls.\n\nRationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.6.3'
  tag level: 2

  describe.one do
    describe package('selinux') do
      it { should be_installed }
    end

    describe command('sestatus') do
      it { should exist }
    end

    describe package('apparmor') do
      it { should be_installed }
    end

    describe command('apparmor_status') do
      it { should exist }
    end
  end
end
