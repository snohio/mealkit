# frozen_string_literal: true

#
# Cookbook:: remediation
# Recipe:: remediation
#
# Copyright:: 2019, Chef Software
#

# benchmark_platform can be in an String for single OS or can be as an Array and this got handle by
# 'platform_family?'( expected values :https://docs.chef.io/infra_language/checking_platforms/#platform_family-values)
# And if the profile is meant to run on any platform we have to add `benchmark_platform` as `all_os`
benchmark_platform = node[cookbook_name]['attributes']['benchmark_platform']
if platform_family?(benchmark_platform) || benchmark_platform.eql?("all_os")
  # Iterate through controls which are configured with this cookbook's namespace to call `remediation_runner`
  node[cookbook_name]['attributes']['controls'].each do |control|
    remediation_runner control['id'] do
      action :run
      remediation_control control
    end
  end

  remediation_runner 'report' do
    action :report
    only_if { node['report_output'] == true }
  end
else
  Chef::Log.info "This cookbook is only for a #{benchmark_platform} platform"
end
