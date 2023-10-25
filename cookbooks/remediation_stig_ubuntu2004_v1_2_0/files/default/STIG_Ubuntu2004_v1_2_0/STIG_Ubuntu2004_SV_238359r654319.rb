# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238359r654319 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238359r654319')
    @title = 'The Ubuntu operating systems Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
    @scored = true
    @level = 1
    @identifier = 'SV_238359r654319'
    @description = '
    "<VulnDiscussion>Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor. \n \nAccordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization. \n \nVerifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = ''
    @commands = [{"local"=>"echo 'Automated remediation unavailable. Please remediate manually:\nConfigure APT to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. \nRemove/update any APT configuration files that contain the variable \"AllowUnauthenticated\" to \"false\", or remove \"AllowUnauthenticated\" entirely from each file. Below is an example of setting the \"AllowUnauthenticated\" variable to \"false\": \nAPT::Get::AllowUnauthenticated \"false\";'\n"}]
  end
end
