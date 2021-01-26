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

title '5.1 Configure cron'

control 'cis-dil-benchmark-5.1.1' do
  title 'Ensure cron daemon is enabled'
  desc  '
    The cron daemon is used to execute batch jobs on the system.

    Rationale:

    While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include
    security monitoring that have to run, and cron is used to execute them.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.1'
  tag level: 1

  describe.one do
    %w[cron crond].each do |s|
      describe service(s) do
        it { should be_enabled }
        it { should be_running }
      end
    end
  end
end

control 'cis-dil-benchmark-5.1.2' do
  title 'Ensure permissions on /etc/crontab are configured'
  desc  '
    The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root
    is the user and group owner of the file and that only the owner can access the file.

    Rationale:

    This file contains information on what system jobs are run by cron. Write access to these files could provide
    unprivileged users with the ability to elevate their privileges. Read access to these files could provide user
    with the ability to gain insight on system jobs that run on the system and could provide them a way to gain
    unauthorized privileged access.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.2'
  tag level: 1

  describe file('/etc/crontab') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.3' do
  title 'Ensure permissions on /etc/cron.hourly are configured'
  desc  '
    This directory contains system cron jobs that need to run on an hourly basis. The files in this
    directory cannot be manipulated by the crontab command, but are instead edited by system administrators
    using a text editor. The commands below restrict read/write and search access to user and group root,
    preventing regular users from accessing this directory.

    Rationale:

    Granting write access to this directory for non-privileged users could provide them the means
    for gaining unauthorized elevated privileges. Granting read access to this directory could give
    an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.3'
  tag level: 1

  describe file('/etc/cron.hourly') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.4' do
  title 'Ensure permissions on /etc/cron.daily are configured'
  desc  '
    The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis.
    The files in this directory cannot be manipulated by the crontab command, but are instead edited
    by system administrators using a text editor. The commands below restrict read/write and search
    access to user and group root, preventing regular users from accessing this directory.

    Rationale:

    Granting write access to this directory for non-privileged users could provide them the means for gaining
    unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user
    insight in how to gain elevated privileges or circumvent auditing controls.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.4'
  tag level: 1

  describe file('/etc/cron.daily') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.5' do
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc  '
    The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files
    in this directory cannot be manipulated by the crontab command, but are instead edited by system
    administrators using a text editor. The commands below restrict read/write and search access to user
    and group root, preventing regular users from accessing this directory.

    Rationale:

    Granting write access to this directory for non-privileged users could provide them the means for gaining
    unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user
    insight in how to gain elevated privileges or circumvent auditing controls.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.5'
  tag level: 1

  describe file('/etc/cron.weekly') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.6' do
  title 'Ensure permissions on /etc/cron.monthly are configured'
  desc  '
    The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files
    in this directory cannot be manipulated by the crontab command, but are instead edited by system
    administrators using a text editor. The commands below restrict read/write and search access to user and
    group root, preventing regular users from accessing this directory.

    Rationale:

    Granting write access to this directory for non-privileged users could provide them the means for gaining
    unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user
    insight in how to gain elevated privileges or circumvent auditing controls.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.6'
  tag level: 1

  describe file('/etc/cron.monthly') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.7' do
  title 'Ensure permissions on /etc/cron.d are configured'
  desc  '
    The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly,
    daily weekly and monthly jobs from /etc/crontab, but require more granular control as to when they run.
    The files in this directory cannot be manipulated by the crontab command, but are instead edited by system
    administrators using a text editor. The commands below restrict read/write and search access to user and group
    root, preventing regular users from accessing this directory.

    Rationale:

    Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized
    elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain
    elevated privileges or circumvent auditing controls.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.7'
  tag level: 1

  describe file('/etc/cron.d') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'cis-dil-benchmark-5.1.8' do
  title 'Ensure at/cron is restricted to authorized users'
  desc  '
    Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services.
    If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked.
    Any user not specifically defined in those files is allowed to use at and cron. By removing the files,
    only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron.

    Note that even though a given user is not listed in cron.allow, cron jobs can still be run as that user.
    The cron.allow file only controls administrative access to the crontab command for scheduling and modifying
    cron jobs.

    Rationale:

    On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file
    to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list.
    In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:5.1.8'
  tag level: 1

  %w[cron at].each do |s|
    describe file("/etc/#{s}.deny") do
      it { should_not exist }
    end

    describe file("/etc/#{s}.allow") do
      it { should exist }
      it { should_not be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should_not be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  end
end
