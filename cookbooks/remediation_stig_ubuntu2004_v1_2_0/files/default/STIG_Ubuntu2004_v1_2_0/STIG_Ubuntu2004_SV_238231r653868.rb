# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238231r653868 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238231r653868')
    @title = 'The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials.'
    @scored = true
    @level = 1
    @identifier = 'SV_238231r653868'
    @description = '
    "<VulnDiscussion>The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access. \n \nDoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238231r653868.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238231r653868.sh"}]
  end
end
