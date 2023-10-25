# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238304r654087 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238304r654087')
    @title = 'The Ubuntu operating system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.'
    @scored = true
    @level = 1
    @identifier = 'SV_238304r654087'
    @description = '
    "<VulnDiscussion>In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations. \n \nSome programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.\n\nSatisfies: SRG-OS-000326-GPOS-00126, SRG-OS-000327-GPOS-00127</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238304r654087.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238304r654087.sh"}]
  end
end
