name 'enforce'

# Where to find cookbooks:
default_source :chef_repo, '~/mealkit/cookbooks'

# run_list: chef-client will run these recipes in the order specified.
run_list 'mealkit::default'

# atttributes

default['audit']['reporter'] = 'chef-server-automate'
default['mealkit']['mode'] = 'enforce'
