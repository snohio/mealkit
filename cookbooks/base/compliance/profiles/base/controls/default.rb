# copyright: 2023, Mike Butler

control 'chef-client-schedule' do
  impact 0.7
  title 'Run the chef-client every 5 minutes'
  describe systemd_service('chef-client.timer') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }      
  end
  describe file('/etc/systemd/system/chef-client.timer') do
    its('content') { should include('OnUnitActiveSec=5min') }
  end
end
