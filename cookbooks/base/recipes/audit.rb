#
# Cookbook:: base
# Recipe:: audit
#
# Copyright:: 2024, The Authors, All Rights Reserved.
# This recipe holds all of the audit logic. It applies the waiver file

if platform?('ubuntu')
  include_profile 'benchmarks::stig-canonicalubuntu20.04lts-cationly'

  cookbook_file '/etc/chef/waiver.yaml' do
    source 'waiver.yaml'
    owner  'root'
    group  'root'
    action :create
  end
  node.default['audit']['waiver_file'] = '/etc/chef/waiver.yaml'

else
  log 'unsupported' do
    message 'This is an unsupported OS for Audit'
    level :info
  end

end
