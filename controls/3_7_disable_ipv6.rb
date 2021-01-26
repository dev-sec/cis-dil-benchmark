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

title '3.7 Disable IPv6'

control 'cis-dil-benchmark-3.7' do
  title 'Disable IPv6'
  desc  "Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.\n\nRationale: If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.7'
  tag level: 2

  only_if { cis_level == 2 }

  describe 'cis-dil-benchmark-3.7' do
    skip 'Not implemented'
  end
end
