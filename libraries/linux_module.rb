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

class LinuxModule < Inspec.resource(1)
  name 'linux_module'
  desc 'Custom resource to audit Linux kernel modules (based on official kernel_module resource in inspec 1.27.0)'
  example "
    describe linux_module('cramfs') do
      it { should_not be_loaded }
      its(:command) { should match(%r{^install /bin/true%}) }
    end
  "

  def initialize(modulename = nil)
    @module = modulename
  end

  def loaded?
    lsmod_cmd = if inspec.os.redhat? || inspec.os.name == 'fedora'
                  '/sbin/lsmod'
                else
                  'lsmod'
                end

    # get list of all modules
    cmd = inspec.command(lsmod_cmd)
    return false if cmd.exit_status != 0

    # check if module is loaded
    re = Regexp.new('^' + Regexp.quote(@module) + '\s')
    found = cmd.stdout.match(re)
    !found.nil?
  end

  def version
    modinfo_cmd = if inspec.os.redhat? || inspec.os.name == 'fedora'
                    "/sbin/modinfo -F version #{@module}"
                  else
                    "modinfo -F version #{@module}"
                  end

    cmd = inspec.command(modinfo_cmd)
    cmd.exit_status.zero? ? cmd.stdout.delete("\n") : nil
  end

  def command
    modinfo_cmd = "/sbin/modprobe -n -v #{@module} | awk '{$1=$1;print}'"

    cmd = inspec.command(modinfo_cmd)
    cmd.exit_status.zero? ? cmd.stdout.delete("\n") : nil
  end

  def to_s
    "Kernel Module #{@module}"
  end
end
