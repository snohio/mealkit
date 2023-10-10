# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238283r654024 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238283r654024')
    @title = 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the setfacl command.'
    @scored = true
    @level = 1
    @identifier = 'SV_238283r654024'
    @description = '
    "<VulnDiscussion>Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n \nAudit records can be generated from various components within the information system (e.g., module or policy filter).</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238283r654024.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238283r654024.sh"}]
  end
end