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

title '3.1 Network Parameters (Host Only)'

control 'cis-dil-benchmark-3.1.1' do
  title 'Ensure IP forwarding is disabled'
  desc  "The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not.\n\nRationale: Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.1.1'
  tag level: 1

  %w[
    net.ipv4.ip_forward
    net.ipv6.conf.all.forwarding
  ].each do |kp|
    describe kernel_parameter(kp) do
      its('value') { should_not be_nil }
      its('value') { should cmp 0 }
    end
  end
end

control 'cis-dil-benchmark-3.1.2' do
  title 'Ensure packet redirect sending is disabled'
  desc  "ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.\n\nRationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system."
  impact 1.0

  tag cis: 'distribution-independent-linux:3.1.2'
  tag level: 1

  %w[
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.default.send_redirects
  ].each do |kp|
    describe kernel_parameter(kp) do
      its('value') { should_not be_nil }
      its('value') { should cmp 0 }
    end
  end
end
