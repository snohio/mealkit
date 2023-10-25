# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238369r654282 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238369r654282')
    @title = 'The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution.'
    @scored = true
    @level = 1
    @identifier = 'SV_238369r654282'
    @description = '
    "<VulnDiscussion>Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism. \n \nExamples of attacks are buffer overflow attacks.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238369r654282.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238369r654282.sh"}]
  end
end
