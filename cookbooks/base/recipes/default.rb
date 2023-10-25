#
# Cookbook:: base
# Recipe:: default
#
# Copyright:: 2023, The Authors, All Rights Reserved.

if node['mealkit']['mode'] == 'client'

  include_recipe 'base::chef_client'

 elsif node['mealkit']['mode'] == 'audit'

  include_recipe 'base::chef_client'
  include_recipe 'base::audit'

 elsif node['mealkit']['mode'] == 'enforce'

  include_recipe 'base::chef_client'
  include_recipe 'base::audit'
  include_recipe 'base::enforce'

else
  log 'No Mealkit MODE Attribute to apply' do
    level :info
  end

end
