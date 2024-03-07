#
# Cookbook:: base
# Recipe:: enforce
#
# Copyright:: 2024, Progress Chef, All Rights Reserved.
# This recipe applies the Remediation Content.

if platform?('ubuntu')
  include_recipe 'remediation_stig_ubuntu2004_v1_2_0_wrapper::default'

else
  log 'unsupported' do
    message 'This is an unsupported OS for Enforcement Cookbooks'
    level :info
  end

end
