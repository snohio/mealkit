# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238209r653802 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238209r653802')
    @title = 'The Ubuntu operating system default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.'
    @scored = true
    @level = 1
    @identifier = 'SV_238209r653802'
    @description = '
    "<VulnDiscussion>Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238209r653802.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238209r653802.sh"}]
  end
end
