# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238225r653850 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238225r653850')
    @title = 'The Ubuntu operating system must enforce a minimum 15-character password length.'
    @scored = true
    @level = 1
    @identifier = 'SV_238225r653850'
    @description = '
    "<VulnDiscussion>The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. \n \nPassword complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238225r653850.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238225r653850.sh"}]
  end
end
