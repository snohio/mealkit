# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238297r802387 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238297r802387')
    @title = 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the delete_module syscall.'
    @scored = true
    @level = 1
    @identifier = 'SV_238297r802387'
    @description = '
    "<VulnDiscussion>Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000477-GPOS-00222</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238297r802387.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238297r802387.sh"}]
  end
end
