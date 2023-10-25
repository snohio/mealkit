# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238330r654165 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238330r654165')
    @title = 'The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
    @scored = true
    @level = 1
    @identifier = 'SV_238330r654165'
    @description = '
    "<VulnDiscussion>Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. \n \nOperating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238330r654165.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238330r654165.sh"}]
  end
end
