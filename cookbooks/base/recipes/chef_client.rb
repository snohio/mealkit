#
# Cookbook:: base
# Recipe:: chef_client
#
# Copyright:: 2024, The Authors, All Rights Reserved.

include_profile 'base::base'

if platform?('ubuntu')
  chef_client_cron 'chef_client_run' do
    action :remove
  end

  cron_d 'chef_client_run' do
    action :delete
  end

  chef_client_systemd_timer 'chef-client' do
    interval '5min'
    accept_chef_license true
    splay '10seconds'
  end

else
  log 'unsupported' do
    message 'This is an unsupported OS for this Base Cookbook'
    level :info
  end

end
