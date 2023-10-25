# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238210r653805 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238210r653805')
    @title = 'The Ubuntu operating system must implement smart card logins for multifactor authentication for local and network access to privileged and non-privileged accounts.'
    @scored = true
    @level = 1
    @identifier = 'SV_238210r653805'
    @description = '
    "<VulnDiscussion>Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. \n \nMultifactor authentication requires using two or more factors to achieve authentication. \n \nFactors include:  \n1) something a user knows (e.g., password/PIN); \n2) something a user has (e.g., cryptographic identification device, token); and \n3) something a user is (e.g., biometric). \n \nA privileged account is defined as an information system account with authorizations of a privileged user. \n \nNetwork access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet). \n \nThe DoD CAC with DoD-approved PKI is an example of multifactor authentication.\n\nSatisfies: SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238210r653805.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238210r653805.sh"}]
  end
end
