# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238200r653775 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238200r653775')
    @title = 'The Ubuntu operating system must allow users to directly initiate a session lock for all connection types.'
    @scored = true
    @level = 1
    @identifier = 'SV_238200r653775'
    @description = '
    "<VulnDiscussion>A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. \n \nThe session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, the Ubuntu operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session if they need to temporarily vacate the immediate physical vicinity.\n\nSatisfies: SRG-OS-000030-GPOS-00011, SRG-OS-000031-GPOS-00012</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238200r653775.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238200r653775.sh"}]
  end
end
