# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238370r654285 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238370r654285')
    @title = 'The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.'
    @scored = true
    @level = 1
    @identifier = 'SV_238370r654285'
    @description = '
    "<VulnDiscussion>Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238370r654285.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238370r654285.sh"}]
  end
end
