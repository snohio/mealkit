#
# Cookbook:: base
# Recipe:: enforce
#
# Copyright:: 2022, The Authors, All Rights Reserved.
# This cookbook holds all of the audit logic. There should only be include_profiles here and evaluates OS type and Version info to know which to run.

if platform?('ubuntu')
  include_recipe 'remediation_stig_ubuntu2004_v1_2_0_wrapper::default'

else
  log 'unsupported' do
    message 'This is an unsupported OS for Enforcement Cookbooks'
    level :info
  end

end
