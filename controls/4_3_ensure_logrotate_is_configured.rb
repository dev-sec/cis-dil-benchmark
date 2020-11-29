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
#

title '4.3 Ensure logrotate is configured'

control 'cis-dil-benchmark-4.3' do
  title 'Ensure logrotate is configured'
  desc  "The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageably large. The file /etc/logrotate.d/syslog is the configuration file used to rotate log files created by syslog or rsyslog.\n\nRationale: By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files."
  impact 0.0

  tag cis: 'distribution-independent-linux:4.3'
  tag level: 1

  # Use an expected readable inventory file
  describe file('/root/cis_expected_logrotate') do
    it { should exist }
  end

  describe command('grep "" /etc/logrotate.conf /etc/logrotate.d/* | diff /root/cis_expected_logrotate -') do
    its('stdout') { should eq '' }
  end
end
