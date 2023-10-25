# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_251505r808512 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_251505r808512')
    @title = 'The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.'
    @scored = true
    @level = 1
    @identifier = 'SV_251505r808512'
    @description = '
    "<VulnDiscussion>Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.\n\nPeripherals include, but are not limited to, such devices as flash drives, external storage, and printers.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_251505r808512.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_251505r808512.sh"}]
  end
end
