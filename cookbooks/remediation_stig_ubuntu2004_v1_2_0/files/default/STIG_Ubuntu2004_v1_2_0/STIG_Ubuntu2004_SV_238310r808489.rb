# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238310r808489 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238310r808489')
    @title = 'The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.'
    @scored = true
    @level = 1
    @identifier = 'SV_238310r808489'
    @description = '
    "<VulnDiscussion>Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n \nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nThe system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238310r808489.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238310r808489.sh"}]
  end
end