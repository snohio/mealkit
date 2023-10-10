# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238233r653874 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238233r653874')
    @title = 'The Ubuntu operating system for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.'
    @scored = true
    @level = 1
    @identifier = 'SV_238233r653874'
    @description = '
    "<VulnDiscussion>Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238233r653874.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238233r653874.sh"}]
  end
end
