#
# Cookbook:: base
# Recipe:: audit
#
# Copyright:: 2022, The Authors, All Rights Reserved.
# This cookbook holds all of the audit logic. There should only be include_profiles here and evaluates OS type and Version info to know which to run.

if platform?('ubuntu')
  include_profile 'stig_benchmarks::stig-canonicalubuntu20.04lts-cationly'

  cookbook_file '/tmp/waiver-ubuntu.yaml' do
    source 'waiver-ubuntu.yaml'
    owner  'root'
    group  'root'
    action :create
  end
  node.default['audit']['waiver_file'] = '/tmp/waiver-ubuntu.yaml'

else
  log 'unsupported' do
    message 'This is an unsupported OS for Audit'
    level :info
  end

end
