# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238237r653886 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238237r653886')
    @title = 'The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
    @scored = true
    @level = 1
    @identifier = 'SV_238237r653886'
    @description = '
    "<VulnDiscussion>Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238237r653886.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238237r653886.sh"}]
  end
end
