# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238301r654078 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238301r654078')
    @title = 'The Ubuntu operating system must configure audit tools to be owned by root.'
    @scored = true
    @level = 1
    @identifier = 'SV_238301r654078'
    @description = '
    "<VulnDiscussion>Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. \n \nOperating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools. \n \nAudit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.\n\nSatisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = ''
    @commands = [{"local"=>"echo 'Automated remediation unavailable. Please remediate manually:\nConfigure the audit tools on the Ubuntu operating system to be protected from unauthorized access by setting the file owner as  root.\nsudo chown root [audit_tool]'\n"}]
  end
end
