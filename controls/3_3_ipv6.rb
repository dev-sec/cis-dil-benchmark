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

title '3.3 IPv6'

control 'cis-dil-benchmark-3.3.1' do
  title 'Ensure IPv6 router advertisements are not accepted'
  desc  "This setting disables the system's ability to accept IPv6 router advertisements.\n\nRationale: It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.1'
  tag level: 1

  only_if do
    ipv6_enabled = true

    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      grub_file = file(f)
      if !grub_file.content.nil? && grub_file.content.match(/ipv6\.disable=1/)
        ipv6_enabled = false
        break
      end
    end

    ipv6_enabled
  end

  %w(net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra).each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end

control 'cis-dil-benchmark-3.3.2' do
  title 'Ensure IPv6 redirects are not accepted'
  desc  "This setting prevents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic.\n\nRationale: It is recommended that systems not accept ICMP redirects as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.2'
  tag level: 1

  only_if do
    ipv6_enabled = true

    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      grub_file = file(f)
      if !grub_file.content.nil? && grub_file.content.match(/ipv6\.disable=1/)
        ipv6_enabled = false
        break
      end
    end

    ipv6_enabled
  end

  %w(net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects).each do |kp|
    describe kernel_parameter(kp) do
      its(:value) { should_not be_nil }
      its(:value) { should eq 0 }
    end
  end
end

control 'cis-dil-benchmark-3.3.3' do
  title 'Ensure IPv6 is disabled'
  desc  "Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.\n\nRationale: If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.3.3'
  tag level: 1

  describe.one do
    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      describe file(f) do
        its(:content) { should match(/ipv6\.disable=1/) }
      end
    end
  end
end
