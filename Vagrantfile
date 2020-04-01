#!/usr/bin/env ruby
# frozen_string_literal: true

provisioning_script = <<~SCRIPT
  apt update -qq && \
  apt install -y libdbus-1-dev gnome-keyring libssl-dev dbus-x11 curl
SCRIPT

Vagrant.configure('2') do |config|
  config.vm.provider 'virtualbox' do |v|
    v.memory = 2048
    v.cpus = 2
  end

  config.vm.box = 'ubuntu/bionic64'
  config.vm.provision 'shell',
                      inline: provisioning_script,
                      privileged: true
  config.vm.provision 'shell',
                      inline: 'curl https://sh.rustup.rs -sSf | ' \
                        'sh -s -- -y --profile minimal --default-toolchain '\
                        'stable && '\
                        'mkdir -p ~/.cache ~/.local/share/keyrings',
                      privileged: false
  config.vm.provision "file", source: "ci/test.sh", destination: "test.sh"
end
