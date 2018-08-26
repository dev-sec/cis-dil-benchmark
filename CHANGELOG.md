# Change Log

## [0.2.0](https://github.com/dev-sec/cis-dil-benchmark/tree/0.2.0) (2018-08-26)
**Closed issues:**

- Debian uses group 42 \('shadow'\) as group for shadow files [\#31](https://github.com/dev-sec/cis-dil-benchmark/issues/31)
- inspec fails to run due to undefined method 'passwords' [\#5](https://github.com/dev-sec/cis-dil-benchmark/issues/5)
- Wrong modinfo option [\#4](https://github.com/dev-sec/cis-dil-benchmark/issues/4)
- Getting undefined method `split' for nil:NilClass \(NoMethodError\) on MacOS [\#3](https://github.com/dev-sec/cis-dil-benchmark/issues/3)
- Update 6\_2\_user\_and\_group\_settings.rb to mock empty array. [\#1](https://github.com/dev-sec/cis-dil-benchmark/issues/1)

**Merged pull requests:**

- Modified controls to use the built in kernel\_module of Inspec [\#49](https://github.com/dev-sec/cis-dil-benchmark/pull/49) ([itoperatorguy](https://github.com/itoperatorguy))
- handle potential leading space for umask regex [\#47](https://github.com/dev-sec/cis-dil-benchmark/pull/47) ([veetow](https://github.com/veetow))
- increase rubocop block length [\#44](https://github.com/dev-sec/cis-dil-benchmark/pull/44) ([chris-rock](https://github.com/chris-rock))
- Fix shadow user and password deprecations [\#42](https://github.com/dev-sec/cis-dil-benchmark/pull/42) ([timstoop](https://github.com/timstoop))
- Fix a compare with zero. [\#41](https://github.com/dev-sec/cis-dil-benchmark/pull/41) ([timstoop](https://github.com/timstoop))
- Also allow pool to be set. [\#39](https://github.com/dev-sec/cis-dil-benchmark/pull/39) ([timstoop](https://github.com/timstoop))
- Make the 4.1.15 check less strict. [\#38](https://github.com/dev-sec/cis-dil-benchmark/pull/38) ([timstoop](https://github.com/timstoop))
- According to CIS DIL 1.1.0, wtmp and btmp should be tagged logins. [\#37](https://github.com/dev-sec/cis-dil-benchmark/pull/37) ([timstoop](https://github.com/timstoop))
- This fixes for the syntax for CIS DIL 4.1.6 to require just one valid describe. [\#36](https://github.com/dev-sec/cis-dil-benchmark/pull/36) ([timstoop](https://github.com/timstoop))
- Make the check slightly less strict. [\#35](https://github.com/dev-sec/cis-dil-benchmark/pull/35) ([timstoop](https://github.com/timstoop))
- Fix deprecation warnings. [\#34](https://github.com/dev-sec/cis-dil-benchmark/pull/34) ([timstoop](https://github.com/timstoop))
- Debian uses group 42 shadow [\#33](https://github.com/dev-sec/cis-dil-benchmark/pull/33) ([timstoop](https://github.com/timstoop))
- updated regex to account for sha512 not being first option [\#30](https://github.com/dev-sec/cis-dil-benchmark/pull/30) ([crashdummymch](https://github.com/crashdummymch))
- Adjust modprobe check to remove false positives. [\#28](https://github.com/dev-sec/cis-dil-benchmark/pull/28) ([millerthomasj](https://github.com/millerthomasj))
- Update umask checks for Centos7 and Amazon Linux. [\#27](https://github.com/dev-sec/cis-dil-benchmark/pull/27) ([millerthomasj](https://github.com/millerthomasj))
- Update password quality checks for pam. [\#25](https://github.com/dev-sec/cis-dil-benchmark/pull/25) ([millerthomasj](https://github.com/millerthomasj))
- Allowed MACs should allow for greater security [\#24](https://github.com/dev-sec/cis-dil-benchmark/pull/24) ([millerthomasj](https://github.com/millerthomasj))
- pin inspec 2.1.0 [\#23](https://github.com/dev-sec/cis-dil-benchmark/pull/23) ([chris-rock](https://github.com/chris-rock))
- Should check one of cron or crond not both. [\#22](https://github.com/dev-sec/cis-dil-benchmark/pull/22) ([millerthomasj](https://github.com/millerthomasj))
- Add auditd fixes for Centos7 [\#21](https://github.com/dev-sec/cis-dil-benchmark/pull/21) ([millerthomasj](https://github.com/millerthomasj))
- Add tcp\_wrappers package for both Centos7 and Amazon Linux. [\#20](https://github.com/dev-sec/cis-dil-benchmark/pull/20) ([millerthomasj](https://github.com/millerthomasj))
- Add additional filepath for chrony.conf on Centos7. [\#19](https://github.com/dev-sec/cis-dil-benchmark/pull/19) ([millerthomasj](https://github.com/millerthomasj))
- Ntpd run as user [\#18](https://github.com/dev-sec/cis-dil-benchmark/pull/18) ([millerthomasj](https://github.com/millerthomasj))
- Centos7 uses grub2 by default, add checks for proper file. [\#17](https://github.com/dev-sec/cis-dil-benchmark/pull/17) ([millerthomasj](https://github.com/millerthomasj))
- On both Centos7 and latest Amazon Linux ansible auto creates cron ent… [\#16](https://github.com/dev-sec/cis-dil-benchmark/pull/16) ([millerthomasj](https://github.com/millerthomasj))
- updated regex to detect proper string [\#15](https://github.com/dev-sec/cis-dil-benchmark/pull/15) ([crashdummymch](https://github.com/crashdummymch))
- Undefinedmethod [\#14](https://github.com/dev-sec/cis-dil-benchmark/pull/14) ([crashdummymch](https://github.com/crashdummymch))
- changed command for redhat family to modprobe to properly evaluate test [\#10](https://github.com/dev-sec/cis-dil-benchmark/pull/10) ([crashdummymch](https://github.com/crashdummymch))
- implements inspec check and enables it in travis [\#9](https://github.com/dev-sec/cis-dil-benchmark/pull/9) ([chris-rock](https://github.com/chris-rock))
- use inspec's os\_env split method [\#8](https://github.com/dev-sec/cis-dil-benchmark/pull/8) ([chris-rock](https://github.com/chris-rock))
- Passwords to password [\#6](https://github.com/dev-sec/cis-dil-benchmark/pull/6) ([crashdummymch](https://github.com/crashdummymch))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*