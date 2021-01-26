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

title '1.5 Additional Process Hardening'

control 'cis-dil-benchmark-1.5.1' do
  title 'Ensure core dumps are restricted'
  desc  "A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.\n\nRationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.1'
  tag level: 1

  describe.one do
    describe file('/etc/security/limits.conf') do
      its(:content) { should match(/^\s*\*\s+hard\s+core\s+0\s*(?:#.*)?$/) }
    end

    command('find /etc/security/limits.d -type f').stdout.split.each do |f|
      describe file(f) do
        its(:content) { should match(/^\s*\*\s+hard\s+core\s+0\s*(?:#.*)?$/) }
      end
    end
  end

  describe kernel_parameter('fs.suid_dumpable') do
    its(:value) { should eq 0 }
  end
end

control 'cis-dil-benchmark-1.5.2' do
  title 'Ensure XD/NX support is enabled'
  desc  "Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports the feature.\n\nRationale: Enabling any feature that can protect against buffer overflow attacks enhances the security of the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.5.2'
  tag level: 1

  describe command('dmesg | grep NX') do
    its(:stdout) { should match(/NX \(Execute Disable\) protection: active/) }
  end
end

control 'cis-dil-benchmark-1.5.3' do
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc  "Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.3'
  tag level: 1

  describe kernel_parameter('kernel.randomize_va_space') do
    its(:value) { should eq 2 }
  end
end

control 'cis-dil-benchmark-1.5.4' do
  title 'Ensure prelink is disabled'
  desc  "prelink is a program that modifies ELF shared libraries and ELF dynamically linked binaries in such a way that the time needed for the dynamic linker to perform relocations at startup significantly decreases.\n\nRationale: The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.4'
  tag level: 1

  describe.one do
    describe package('prelink') do
      it { should_not be_installed }
    end

    describe command('prelink') do
      it { should_not exist }
    end
  end
end
