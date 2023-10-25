# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238228r653859 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238228r653859')
    @title = 'The Ubuntu operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.'
    @scored = true
    @level = 1
    @identifier = 'SV_238228r653859'
    @description = '
    "<VulnDiscussion>Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \"pwquality\" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238228r653859.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238228r653859.sh"}]
  end
end
