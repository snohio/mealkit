# frozen_string_literal: true

# Policyfile.rb - Describe how you want Chef Infra Client to build your system.
#
# For more information on the Policyfile feature, visit
# https://docs.chef.io/policyfile.html

# A name that describes what the system you're building with Chef does.
name 'remediation_stig_ubuntu2004_v1_2_0_wrapper'

# Where to find external cookbooks:
default_source :supermarket

# run_list: chef-client will run these recipes in the order specified.
run_list 'remediation_stig_ubuntu2004_v1_2_0_wrapper::default'

# Specify a custom source for a single cookbook:
cookbook 'remediation_stig_ubuntu2004_v1_2_0_wrapper', path: '.'
