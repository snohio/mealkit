# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238363r654320 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238363r654320')
    @title = 'The Ubuntu operating system must implement NIST FIPS-validated cryptography  to protect classified information and for the following to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
    @scored = true
    @level = 1
    @identifier = 'SV_238363r654320'
    @description = '
    "<VulnDiscussion>Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.\n\nSatisfies: SRG-OS-000396-GPOS-00176, SRG-OS-000478-GPOS-00223</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = ''
    @commands = [{"local"=>"echo 'Automated remediation unavailable. Please remediate manually:\nConfigure the system to run in FIPS mode. Add \"fips=1\" to the kernel parameter during the Ubuntu operating systems install. \nEnabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. Refer to the Ubuntu Server 18.04 FIPS 140-2 security policy document for instructions.  \nA subscription to the \"Ubuntu Advantage\" plan is required in order to obtain the FIPS Kernel cryptographic modules and enable FIPS.'\n"}]
  end
end
