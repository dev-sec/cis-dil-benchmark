# frozen_string_literal: true

class GrubConf < Inspec.resource(1)
  name 'grub_conf'

  def locations
    %w[/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst /boot/grub2/grub.cfg]
  end
end
