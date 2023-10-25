# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_251504r808509 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_251504r808509')
    @title = 'The Ubuntu operating system must not allow accounts configured with blank or null passwords.'
    @scored = true
    @level = 1
    @identifier = 'SV_251504r808509'
    @description = '
    "<VulnDiscussion>If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_251504r808509.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_251504r808509.sh"}]
  end
end
