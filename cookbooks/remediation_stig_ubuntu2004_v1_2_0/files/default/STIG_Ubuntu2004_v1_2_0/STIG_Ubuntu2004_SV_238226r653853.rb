# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238226r653853 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238226r653853')
    @title = 'The Ubuntu operating system must enforce password complexity by requiring that at least one special character be used.'
    @scored = true
    @level = 1
    @identifier = 'SV_238226r653853'
    @description = '
    "<VulnDiscussion>Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \n \nPassword complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. \n \nSpecial characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238226r653853.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238226r653853.sh"}]
  end
end
