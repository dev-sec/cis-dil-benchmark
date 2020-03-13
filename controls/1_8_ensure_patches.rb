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

title '1.8 Ensure patches'

control 'cis-dil-benchmark-1.8' do
  title 'Ensure updates, patches, and additional security software are installed'
  desc  "Periodically patches are released for included software either due to security flaws or to include additional functionality.\n\nRationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.8'
  tag level: 1

  describe 'cis-dil-benchmark-1.8' do
    skip 'Not implemented'
  end
end
