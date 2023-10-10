# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238212r653811 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238212r653811')
    @title = 'The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity.'
    @scored = true
    @level = 1
    @identifier = 'SV_238212r653811'
    @description = '
    "<VulnDiscussion>Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. \n \nSession termination terminates all processes associated with a users logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. \n \nConditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. \n \nThis capability is typically reserved for specific Ubuntu operating system functionality where the system owner, data owner, or organization requires additional assurance.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238212r653811.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238212r653811.sh"}]
  end
end
