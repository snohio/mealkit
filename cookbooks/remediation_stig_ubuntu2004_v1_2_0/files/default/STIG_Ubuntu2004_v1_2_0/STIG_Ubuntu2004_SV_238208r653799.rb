# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238208r653799 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238208r653799')
    @title = 'The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles.'
    @scored = true
    @level = 1
    @identifier = 'SV_238208r653799'
    @description = '
    "<VulnDiscussion>Without reauthentication, users may access resources or perform tasks for which they do not have authorization.  \n \nWhen operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.\n\nSatisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238208r653799.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238208r653799.sh"}]
  end
end
