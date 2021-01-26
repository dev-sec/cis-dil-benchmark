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

title '1.2 Configure Software Updates'

control 'cis-dil-benchmark-1.2.1' do
  title 'Ensure package manager repositories are configured'
  desc  "Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.\n\nRationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.2.1'
  tag level: 1

  describe 'cis-dil-benchmark-1.2.1' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.2.2' do
  title 'Ensure GPG keys are configured'
  desc  "Most packages managers implement GPG key signing to verify package integrity during installation.\n\nRationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.2.2'
  tag level: 1

  describe 'cis-dil-benchmark-1.2.2' do
    skip 'Not implemented'
  end
end
