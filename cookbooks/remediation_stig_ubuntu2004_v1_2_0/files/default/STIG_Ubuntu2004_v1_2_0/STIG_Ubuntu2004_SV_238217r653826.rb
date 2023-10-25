# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238217r653826 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238217r653826')
    @title = 'The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
    @scored = true
    @level = 1
    @identifier = 'SV_238217r653826'
    @description = '
    "<VulnDiscussion>Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  \n \nRemote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.  \n \nNonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.  \n \nLocal maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.  \n \nEncrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. \n \nBy specifying a cipher list with the order of ciphers being in a \"strongest to weakest\" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.\n\nSatisfies: SRG-OS-000424-GPOS-00188, SRG-OS-000033-GPOS-00014, SRG-OS-000394-GPOS-00174</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238217r653826.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238217r653826.sh"}]
  end
end
