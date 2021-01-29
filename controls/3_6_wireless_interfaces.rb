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

title '3.6 Wireless interfaces'

control 'cis-dil-benchmark-3.6' do
  title 'Ensure wireless interfaces are disabled'
  desc  "Wireless networking is used when wired networks are unavailable. Debian contains a wireless tool kit to allow system administrators to configure and use wireless networks.\n\nRationale: If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface."
  impact 0.0

  tag cis: 'distribution-independent-linux:3.6'
  tag level: 1

  describe 'cis-dil-benchmark-3.6' do
    skip 'Not implemented'
  end
end
