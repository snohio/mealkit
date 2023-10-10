# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238218r653829 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238218r653829')
    @title = 'The Ubuntu operating system must not allow unattended or automatic login via SSH.'
    @scored = true
    @level = 1
    @identifier = 'SV_238218r653829'
    @description = '
    "<VulnDiscussion>Failure to restrict system access to authenticated users negatively impacts Ubuntu operating system security.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238218r653829.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238218r653829.sh"}]
  end
end
