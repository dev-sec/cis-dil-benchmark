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
#

title '1.3 Filesystem Integrity Checking'

control 'cis-dil-benchmark-1.3.1' do
  title 'Ensure AIDE is installed'
  desc  "AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.\n\nRationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.3.1'
  tag level: 1

  describe.one do
    describe package('aide') do
      it { should be_installed }
    end

    describe command('aide') do
      it { should exist }
    end
  end
end

control 'cis-dil-benchmark-1.3.2' do
  title 'Ensure filesystem integrity is regularly checked'
  desc  "Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.\n\nRationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.3.2'
  tag level: 1

  describe.one do
    %w[/var/spool/cron/crontabs/root /var/spool/cron/root /etc/crontab].each do |f|
      describe file(f) do
        its('content') { should match(/aide (--check|-C)/) }
      end
    end

    %w[cron.d cron.hourly cron.daily cron.weekly cron.monthly].each do |f|
      command("find /etc/#{f} -type f").stdout.split.each do |entry|
        describe file(entry) do
          its('content') { should match(/aide (--check|-C)/) }
        end
      end
    end
  end
end
