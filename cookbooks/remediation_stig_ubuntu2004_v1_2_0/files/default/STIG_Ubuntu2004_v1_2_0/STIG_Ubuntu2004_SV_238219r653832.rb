# frozen_string_literal: true

require_relative 'cis_remediation'

class STIG_Ubuntu2004_SV_238219r653832 < CISRemediation
  def initialize
    super('STIG_Ubuntu2004_SV_238219r653832')
    @title = 'The Ubuntu operating system must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.'
    @scored = true
    @level = 1
    @identifier = 'SV_238219r653832'
    @description = '
    "<VulnDiscussion>The security risk of using X11 forwarding is that the clients X11 display server may be exposed to attack when the SSH client requests forwarding.  A System Administrator may have a stance in which they want to protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a no setting. \n \nX11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the users X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled. \n \nIf X11 services are not required for the systems intended function, they should be disabled or restricted as appropriate to the system\u2019s needs.</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>"
    '
    @script_file = 'STIG_Ubuntu2004_SV_238219r653832.sh'
    @commands = [{"script_bash"=>"bash #{@script_directory}/STIG_Ubuntu2004_SV_238219r653832.sh"}]
  end
end
