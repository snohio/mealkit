# encoding: UTF-8

control "xccdf_mil.disa.stig_rule_SV-238200r653775_rule" do
  title "The Ubuntu operating system must allow users to directly initiate a session lock for all connection types."
  desc  "
    Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
    
    The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, the Ubuntu operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session if they need to temporarily vacate the immediate physical vicinity.
    
    Satisfies: SRG-OS-000030-GPOS-00011, SRG-OS-000031-GPOS-00012
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000058"
  tag nist: ["NIST SP 800-53", "3", "AC-11 a"]
  tag nist: ["NIST SP 800-53A", "1", "AC-11"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-11 a"]
  tag cci: "CCI-000060"
  tag nist: ["NIST SP 800-53", "3", "AC-11 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-11 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-11 (1)"]
  describe package("vlock") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238202r653781_rule" do
  title "The Ubuntu operating system must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction."
  desc  "
    Vulnerability Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000198"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (d)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (d)"]
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+(\d*)/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MIN_DAYS\s+(\d*)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238203r653784_rule" do
  title "The Ubuntu operating system must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."
  desc  "
    Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000199"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (d)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (d)"]
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(\d*)/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MAX_DAYS\s+(\d*)/).flatten.each do |entry|
    describe entry do
      it { should cmp > 0 }
    end
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MAX_DAYS\s+(\d*)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238208r653799_rule" do
  title "The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles."
  desc  "
    Vulnerability Discussion: Without reauthentication, users may access resources or perform tasks for which they do not have authorization.
    
    When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.
    
    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe file("/etc/sudoers") do
    its("content") { should_not match(/(?i)nopasswd/) }
  end
  describe file("/etc/sudoers") do
    its("content") { should_not match(/(?i)!authenticate/) }
  end
  files = command("find /etc/sudoers.d -type f -regex .\\*/.\\*").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /(?i)nopasswd/ } do
    it { should be_empty }
  end
  files = command("find /etc/sudoers.d -type f -regex .\\*/.\\*").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /(?i)!authenticate/ } do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238209r653802_rule" do
  title "The Ubuntu operating system default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files."
  desc  "
    Vulnerability Discussion: Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*UMASK\s+(\d*)/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*UMASK\s+(\d*)/).flatten.each do |entry|
    describe entry do
      it { should eq "077" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238210r653805_rule" do
  title "The Ubuntu operating system must implement smart card logins for multifactor authentication for local and network access to privileged and non-privileged accounts."
  desc  "
    Vulnerability Discussion: Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.
    
    Multifactor authentication requires using two or more factors to achieve authentication.
    
    Factors include:
    1) something a user knows (e.g., password/PIN);
    2) something a user has (e.g., cryptographic identification device, token); and
    3) something a user is (e.g., biometric).
    
    A privileged account is defined as an information system account with authorizations of a privileged user.
    
    Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).
    
    The DoD CAC with DoD-approved PKI is an example of multifactor authentication.
    
    Satisfies: SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000765"
  tag nist: ["NIST SP 800-53", "3", "IA-2 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-2 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (1)"]
  tag cci: "CCI-000766"
  tag nist: ["NIST SP 800-53", "3", "IA-2 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-2 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (2)"]
  tag cci: "CCI-000767"
  tag nist: ["NIST SP 800-53", "3", "IA-2 (3)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-2 (3).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (3)"]
  tag cci: "CCI-000768"
  tag nist: ["NIST SP 800-53", "3", "IA-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-2 (4).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (4)"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PubkeyAuthentication[ \t]+(\w+)\s*(?:#.*|$)/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PubkeyAuthentication[ \t]+(\w+)\s*(?:#.*|$)/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
  describe package("libpam-pkcs11") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238211r653808_rule" do
  title "The Ubuntu operating system must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."
  desc  "
    Vulnerability Discussion: Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000877"
  tag nist: ["NIST SP 800-53", "3", "MA-4 c"]
  tag nist: ["NIST SP 800-53A", "1", "MA-4.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 c"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*UsePAM\s+(\w*)/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*UsePAM\s+(\w*)/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238212r653811_rule" do
  title "The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity."
  desc  "
    Vulnerability Discussion: Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.
    
    Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.
    
    Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.
    
    This capability is typically reserved for specific Ubuntu operating system functionality where the system owner, data owner, or organization requires additional assurance.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000879"
  tag nist: ["NIST SP 800-53", "3", "MA-4 e"]
  tag nist: ["NIST SP 800-53A", "1", "MA-4.1 (vi)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 e"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveCountMax\s+(\d*)/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveCountMax\s+(\d*)/).flatten.each do |entry|
    describe entry do
      it { should cmp == 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238213r653814_rule" do
  title "The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity."
  desc  "
    Vulnerability Discussion: Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.
    
    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001133"
  tag nist: ["NIST SP 800-53", "3", "SC-10"]
  tag nist: ["NIST SP 800-53A", "1", "SC-10.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-10"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveInterval[ \t]+(\d+)\s*(?:#.*|$)/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveInterval[ \t]+(\d+)\s*(?:#.*|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 600 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238216r654316_rule" do
  title "The Ubuntu operating system must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
  desc  "
    Vulnerability Discussion: Without cryptographic integrity protections, information can be altered by unauthorized users without detection.
    
    Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.
    
    Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.
    
    Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.
    
    Satisfies: SRG-OS-000424-GPOS-00188, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001453"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  tag cci: "CCI-002890"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*(?i)MACs(?-i)[ \t]+\"?([\w,-]+)\"?[\s]*(?:|(?:#.*))?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*(?i)MACs(?-i)[ \t]+\"?([\w,-]+)\"?[\s]*(?:|(?:#.*))?$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(hmac-sha2-512)|(hmac-sha2-512,hmac-sha2-256)|(hmac-sha2-256)$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238217r653826_rule" do
  title "The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
  desc  "
    Vulnerability Discussion: Without cryptographic integrity protections, information can be altered by unauthorized users without detection.
    
    Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
    
    Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.
    
    Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.
    
    Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.
    
    By specifying a cipher list with the order of ciphers being in a \"strongest to weakest\" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.
    
    Satisfies: SRG-OS-000424-GPOS-00188, SRG-OS-000033-GPOS-00014, SRG-OS-000394-GPOS-00174
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000068"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  tag cci: "CCI-003123"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*(?i)Ciphers(?-i)[ \t]+\"?([\w,-]+)\"?[\s]*(?:|(?:#.*))?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*(?i)Ciphers(?-i)[ \t]+\"?([\w,-]+)\"?[\s]*(?:|(?:#.*))?$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:(aes256-ctr,aes192-ctr,aes128-ctr)|(aes256-ctr,aes192-ctr)|(aes256-ctr,aes128-ctr)|(aes192-ctr,aes128-ctr)|(aes256-ctr)|(aes192-ctr)|(aes128-ctr))$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238220r653835_rule" do
  title "The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to the proxy display."
  desc  "
    Vulnerability Discussion: When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*(?i)X11UseLocalhost(?-i)\s+"?(\S+?)"?\s*(?:#.*|$)/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*(?i)X11UseLocalhost(?-i)\s+"?(\S+?)"?\s*(?:#.*|$)/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238221r653838_rule" do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one upper-case character be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000192"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ucredit\s*=\s*(-?\d*)\s*(?:#.*)?$/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*ucredit\s*=\s*(-?\d*)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp < 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238222r653841_rule" do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one lower-case character be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000193"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*lcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*lcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238223r653844_rule" do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one numeric character be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000194"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*dcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*dcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238224r653847_rule" do
  title "The Ubuntu operating system must require the change of at least 8 characters when passwords are changed."
  desc  "
    Vulnerability Discussion: If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.
    
    The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.
    
    If the password length is an odd number then number of changed characters must be rounded up.  For example, a password length of 15 characters must require the change of at least 8 characters.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000195"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (b)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (b)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*difok[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*difok[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 8 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238225r653850_rule" do
  title "The Ubuntu operating system must enforce a minimum 15-character password length."
  desc  "
    Vulnerability Discussion: The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.
    
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000205"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (i)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*minlen[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*minlen[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 15 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238226r653853_rule" do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one special character be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-001619"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ocredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*ocredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238227r653856_rule" do
  title "The Ubuntu operating system must prevent the use of dictionary words for passwords."
  desc  "
    Vulnerability Discussion: If the Ubuntu operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*dictcheck[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*dictcheck[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp == 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238228r653859_rule" do
  title "The Ubuntu operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \"pwquality\" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe package("libpam-pwquality") do
    it { should be_installed }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*enforcing[\s]*=[\s]*(\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^\s*enforcing[\s]*=[\s]*(\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp == 1 }
    end
  end
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^\s*\w+[\s]+requisite[\s]+pam_pwquality\.so[\s]+(?:|.+\s+)retry=([\d]+)(?:[\s]|$)/) }
  end
  file("/etc/pam.d/common-password").content.to_s.scan(/^\s*\w+[\s]+requisite[\s]+pam_pwquality\.so[\s]+(?:|.+\s+)retry=([\d]+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 3 }
    end
  end
  file("/etc/pam.d/common-password").content.to_s.scan(/^\s*\w+[\s]+requisite[\s]+pam_pwquality\.so[\s]+(?:|.+\s+)retry=([\d]+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp > 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238229r653862_rule" do
  title "The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
  desc  "
    Vulnerability Discussion: Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.
    
    A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.
    
    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.
    
    This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000185"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (a)"]
  describe file("/etc/pam_pkcs11/pam_pkcs11.conf") do
    its("content") { should match(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/) }
  end
  file("/etc/pam_pkcs11/pam_pkcs11.conf").content.to_s.scan(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/ca/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238230r653865_rule" do
  title "The Ubuntu operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access."
  desc  "
    Vulnerability Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.
    
    Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
    
    A privileged account is defined as an information system account with authorizations of a privileged user.
    
    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
    
    This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001948"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (11)"]
  describe package("libpam-pkcs11") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238231r653868_rule" do
  title "The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials."
  desc  "
    Vulnerability Discussion: The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.
    
    DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001953"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (12)"]
  describe package("opensc-pkcs11") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238232r653871_rule" do
  title "The Ubuntu operating system must electronically verify Personal Identity Verification (PIV) credentials."
  desc  "
    Vulnerability Discussion: The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.
    
    DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001954"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (12)"]
  describe file("/etc/pam_pkcs11/pam_pkcs11.conf") do
    its("content") { should match(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/) }
  end
  file("/etc/pam_pkcs11/pam_pkcs11.conf").content.to_s.scan(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/ocsp_on/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238233r653874_rule" do
  title "The Ubuntu operating system for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network."
  desc  "
    Vulnerability Discussion: Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001991"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (d)"]
  describe file("/etc/pam_pkcs11/pam_pkcs11.conf") do
    its("content") { should match(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/) }
  end
  file("/etc/pam_pkcs11/pam_pkcs11.conf").content.to_s.scan(/^\s*cert_policy\s*=\s*([\w\,"' ]+);\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/(crl_offline|crl_auto)/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238235r802383_rule" do
  title "The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made."
  desc  "
    Vulnerability Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.
    
    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000044"
  tag nist: ["NIST SP 800-53", "3", "AC-7 a"]
  tag nist: ["NIST SP 800-53A", "1", "AC-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 a"]
  tag cci: "CCI-002238"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 b"]
  describe file("/etc/pam.d/common-auth") do
    its("content") { should match(/^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail\s*$/) }
  end
  describe file("/etc/pam.d/common-auth") do
    its("content") { should match(/^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc\s*$/) }
  end
  describe file("/etc/security/faillock.conf") do
    its("content") { should match(/^\s*audit\s*$/) }
  end
  describe file("/etc/security/faillock.conf") do
    its("content") { should match(/^\s*silent\s*$/) }
  end
  describe file("/etc/security/faillock.conf") do
    its("content") { should match(/^\s*deny\s*=\s*([0-9]+)+\s*$/) }
  end
  file("/etc/security/faillock.conf").content.to_s.scan(/^\s*deny\s*=\s*([0-9]+)+\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 3 }
    end
  end
  describe file("/etc/security/faillock.conf") do
    its("content") { should match(/^\s*fail_interval\s*=\s*([0-9]+)+\s*$/) }
  end
  file("/etc/security/faillock.conf").content.to_s.scan(/^\s*fail_interval\s*=\s*([0-9]+)+\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 900 }
    end
  end
  describe file("/etc/security/faillock.conf") do
    its("content") { should match(/^\s*unlock_time\s*=\s*([0-9]+)+\s*$/) }
  end
  file("/etc/security/faillock.conf").content.to_s.scan(/^\s*unlock_time\s*=\s*([0-9]+)+\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp == 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238237r653886_rule" do
  title "The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt."
  desc  "
    Vulnerability Discussion: Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe file("/etc/pam.d/common-auth") do
    its("content") { should match(/^\s*auth\s+required\s+pam_faildelay\.so\s+delay=(\d+)\s*(?:#.*)?$/) }
  end
  file("/etc/pam.d/common-auth").content.to_s.scan(/^\s*auth\s+required\s+pam_faildelay\.so\s+delay=(\d+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 4000000 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238238r653889_rule" do
  title "The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
  desc  "
    Vulnerability Discussion: Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.
    
    To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000476-GPOS-00221
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000018"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001403"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001405"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-002130"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/etc\/passwd(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/etc\/passwd\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238239r653892_rule" do
  title "The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
  desc  "
    Vulnerability Discussion: Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.
    
    To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000458-GPOS-00203, SRG-OS-000476-GPOS-00221
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000018"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001403"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001405"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-002130"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/etc\/group(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/etc\/group\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238240r653895_rule" do
  title "The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
  desc  "
    Vulnerability Discussion: Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.
    
    To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000458-GPOS-00203, SRG-OS-000476-GPOS-00221
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000018"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001403"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001405"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-002130"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/etc\/shadow(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/etc\/shadow\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238241r653898_rule" do
  title "The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
  desc  "
    Vulnerability Discussion: Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.
    
    To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000458-GPOS-00203, SRG-OS-000476-GPOS-00221
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001403"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001405"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-002130"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/etc\/gshadow(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/etc\/gshadow\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238242r653901_rule" do
  title "The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
  desc  "
    Vulnerability Discussion: Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.
    
    To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000458-GPOS-00203, SRG-OS-000476-GPOS-00221
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000018"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001403"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-001405"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  tag cci: "CCI-002130"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/etc\/security\/opasswd(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/etc\/security\/opasswd\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238244r653907_rule" do
  title "The Ubuntu operating system must shut down by default upon audit failure (unless availability is an overriding concern)."
  desc  "
    Vulnerability Discussion: It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.
    
    When availability is an overriding concern, other approved actions in response to an audit failure are as follows:
    
    1) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.
    
    2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000140"
  tag nist: ["NIST SP 800-53", "3", "AU-5 b"]
  tag nist: ["NIST SP 800-53A", "1", "AU-5.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-5 b"]
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*disk_full_action\s+=\s+(HALT|SYSLOG|SINGLE)\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238249r653922_rule" do
  title "The Ubuntu operating system must be configured so that audit configuration files are not write-accessible by unauthorized users."
  desc  "
    Vulnerability Discussion: Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.
    
    Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000171"
  tag nist: ["NIST SP 800-53", "3", "AU-12 b"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 b"]
  command('find /etc/audit/rules.d/ -type f').stdout.split("\n").each do |file|
    describe file(file) do
      it { should_not be_executable.by('owner') }
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should_not be_readable.by('other') }
      it { should_not be_writable.by('other') }
      it { should_not be_executable.by('other') }
    end
  end
  describe file("/etc/audit/audit.rules") do
    it { should_not be_executable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
  describe file("/etc/audit/auditd.conf") do
    it { should_not be_executable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238250r653925_rule" do
  title "The Ubuntu operating system must permit only authorized accounts to own the audit configuration files."
  desc  "
    Vulnerability Discussion: Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.
    
    Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000171"
  tag nist: ["NIST SP 800-53", "3", "AU-12 b"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 b"]
  command('find /etc/audit/rules.d/ -type f').stdout.split("\n").each do |file|
    describe file(file) do
      its('owner') { should eq 'root' }
    end
  end
  describe file("/etc/audit/audit.rules") do
    its('owner') { should eq 'root' }
  end
  describe file("/etc/audit/auditd.conf") do
    its('owner') { should eq 'root' }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238251r653928_rule" do
  title "The Ubuntu operating system must permit only authorized groups to own the audit configuration files."
  desc  "
    Vulnerability Discussion: Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.
    
    Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000171"
  tag nist: ["NIST SP 800-53", "3", "AU-12 b"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 b"]
  command('find /etc/audit/rules.d/ -type f').stdout.split("\n").each do |file|
    describe file(file) do
      its('group') { should eq 'root' }
    end
  end
  describe file("/etc/audit/audit.rules") do
    its('group') { should eq 'root' }
  end
  describe file("/etc/audit/auditd.conf") do
    its('group') { should eq 'root' }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238252r653931_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the su command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/bin\/su\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238253r653934_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chfn command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/chfn\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238254r653937_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the mount command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/mount\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238255r653940_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the umount command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/umount\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238256r653943_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-agent command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/ssh-agent\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238257r653946_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/lib\/openssh\/ssh-keysign\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238258r808474_rule" do
  title "The Ubuntu operating system must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\blsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\blsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\blremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\blremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\blsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\blsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfsetxattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\blremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\blremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfremovexattr\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid=0(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238264r808477_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchownat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\blchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchownat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\blchown\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238268r808480_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bchmod\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchmod\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchmodat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bchmod\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchmod\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfchmodat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238271r808483_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000474-GPOS-00219
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\btruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\btruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bftruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bftruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bcreat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bcreat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopenat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopenat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen_by_handle_at\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen_by_handle_at\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\btruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\btruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bftruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bftruncate\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bcreat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bcreat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopenat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopenat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen_by_handle_at\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bopen_by_handle_at\b\S*\s+(?:-S\s+\S+\s+)*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238277r654006_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the sudo command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/sudo\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238278r654009_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the sudoedit command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/sudoedit\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238279r654012_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chsh command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/chsh\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238280r654015_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the newgrp command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/newgrp\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238281r654018_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chcon command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/chcon\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238282r654021_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the apparmor_parser command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/sbin\/apparmor_parser\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238283r654024_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the setfacl command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/setfacl\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238284r654027_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chacl command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/chacl\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238285r654030_rule" do
  title "The Ubuntu operating system must generate audit records for the use and modification of the tallylog file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/log\/tallylog(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/log\/tallylog\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238286r654033_rule" do
  title "The Ubuntu operating system must generate audit records for the use and modification of faillog file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/log\/faillog(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/log\/faillog\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238287r654036_rule" do
  title "The Ubuntu operating system must generate audit records for the use and modification of the lastlog file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/log\/lastlog(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/log\/lastlog\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238288r654039_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the passwd command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/passwd\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=500\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238289r654042_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the unix_update command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/sbin\/unix_update\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238290r654045_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the gpasswd command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/gpasswd\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238291r654048_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chage command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/chage\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238292r654051_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the usermod command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/sbin\/usermod\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238293r654054_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the crontab command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/bin\/crontab\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238294r654057_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)(?:\s+-S\s+all)?\s+-F\s+path=\/usr\/sbin\/pam_timestamp_check\s+(?:-F\s+perm=[rwa]*x[rwa]*\s+)?-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238295r808486_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000471-GPOS-00216
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\binit_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfinit_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\binit_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bfinit_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset).*(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238297r802387_rule" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the delete_module syscall."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000477-GPOS-00222
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bdelete_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bdelete_module\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238298r654069_rule" do
  title "The Ubuntu operating system must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DoD-defined auditable events and actions in near real time."
  desc  "
    Vulnerability Discussion: Without establishing the when, where, type, source, and outcome of events that occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.
    
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.
    
    Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
    
    Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the operating system does not provide the ability to centrally review the operating system logs, forensic analysis is negatively impacted.
    
    Associating event types with detected events in the Ubuntu operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.
    
    Satisfies: SRG-OS-000122-GPOS-00063, SRG-OS-000037-GPOS-00015, SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000040-GPOS-00018, SRG-OS-000041-GPOS-00019, SRG-OS-000042-GPOS-00020, SRG-OS-000042-GPOS-00021, SRG-OS-000051-GPOS-00024, SRG-OS-000054-GPOS-00025, SRG-OS-000062-GPOS-00031, SRG-OS-000337-GPOS-00129, SRG-OS-000348-GPOS-00136, SRG-OS-000349-GPOS-00137, SRG-OS-000350-GPOS-00138, SRG-OS-000351-GPOS-00139, SRG-OS-000352-GPOS-00140, SRG-OS-000353-GPOS-00141, SRG-OS-000354-GPOS-00142, SRG-OS-000475-GPOS-00220
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000130"
  tag nist: ["NIST SP 800-53", "3", "AU-3"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3"]
  tag cci: "CCI-000131"
  tag nist: ["NIST SP 800-53", "3", "AU-3"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3"]
  tag cci: "CCI-000132"
  tag nist: ["NIST SP 800-53", "3", "AU-3"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3"]
  tag cci: "CCI-000133"
  tag nist: ["NIST SP 800-53", "3", "AU-3"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3"]
  tag cci: "CCI-000134"
  tag nist: ["NIST SP 800-53", "3", "AU-3"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3"]
  tag cci: "CCI-000135"
  tag nist: ["NIST SP 800-53", "3", "AU-3 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3 (1).1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3 (1)"]
  tag cci: "CCI-000154"
  tag nist: ["NIST SP 800-53", "3", "AU-6 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-6 (4).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-6 (4)"]
  tag cci: "CCI-000158"
  tag nist: ["NIST SP 800-53", "3", "AU-7 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-7 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 (1)"]
  tag cci: "CCI-000169"
  tag nist: ["NIST SP 800-53", "3", "AU-12 a"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 a"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001875"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001876"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001877"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001878"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001879"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001880"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 a"]
  tag cci: "CCI-001881"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 b"]
  tag cci: "CCI-001882"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-7 b"]
  tag cci: "CCI-001914"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 (3)"]
  describe package("auditd") do
    it { should be_installed }
  end
  describe service("auditd") do
    it { should be_enabled }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238299r654072_rule" do
  title "The Ubuntu operating system must initiate session audits at system start-up."
  desc  "
    Vulnerability Discussion: If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001464"
  tag nist: ["NIST SP 800-53", "3", "AU-14 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-14 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-14 (1)"]
  describe file("/boot/grub/grub.cfg") do
    its("content") { should match(/^\s*linux\s+(.+)$/) }
  end
  file("/boot/grub/grub.cfg").content.to_s.scan(/^\s*linux\s+(.+)$/).flatten.each do |entry|
    describe entry do
      it { should match(/\baudit=1\b/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238300r654075_rule" do
  title "The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive."
  desc  "
    Vulnerability Discussion: Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.
    
    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.
    
    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
    
    Satisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001493"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-001494"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe 'Manual steps required for this recommendation' do
    skip ('Verify the audit tools are protected from unauthorized access, deletion, or modification by checking the permissive mode.'\
           'If any of the audit tools has a mode more permissive than "0755", this is a finding.'\
           'Configure the audit tools to be protected from unauthorized access by setting the correct permissive mode using the following command:$ sudo chmod 0755 [audit_tool]'\
           'Replace "[audit_tool]" with the audit tool that does not have the correct permissive mode')
  end
end

control "xccdf_mil.disa.stig_rule_SV-238301r654078_rule" do
  title "The Ubuntu operating system must configure audit tools to be owned by root."
  desc  "
    Vulnerability Discussion: Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.
    
    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.
    
    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
    
    Satisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001493"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-001494"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe 'Manual steps required for this recommendation' do
    skip ('Verify the audit tools are owned by "root" to prevent any unauthorized access, deletion, or modification.'\
           'If any of the audit tools are not owned by "root", this is a finding.'\
           'Configure the audit tools to be owned by "root", by running the following command:$ sudo chown root [audit_tool]'\
           'Replace "[audit_tool]" with each audit tool not owned by "root".')
  end
end

control "xccdf_mil.disa.stig_rule_SV-238302r654081_rule" do
  title "The Ubuntu operating system must configure the audit tools to be group-owned by root."
  desc  "
    Vulnerability Discussion: Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.
    
    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.
    
    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
    
    Satisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001493"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-001494"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe 'Manual steps required for this recommendation' do
    skip ('Verify the system commands contained in the following directories are group-owned by "root" with the following command:'\
           '$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \;If any system commands are returned and is not owned by a required system account, this is a finding.'\
           'Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account.$ sudo chgrp root [FILE]')
  end
end

control "xccdf_mil.disa.stig_rule_SV-238304r654087_rule" do
  title "The Ubuntu operating system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions."
  desc  "
    Vulnerability Discussion: In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.
    
    Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.
    
    Satisfies: SRG-OS-000326-GPOS-00126, SRG-OS-000327-GPOS-00127
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002233"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (8)"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bexecve\b\S*\s+(?:-S\s+\S+\s+)*-C\s+uid!=euid\s+-F\s+euid=0(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
   its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bexecve\b\S*\s+(?:-S\s+\S+\s+)*-C\s+gid!=egid\s+-F\s+egid=0(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bexecve\b\S*\s+(?:-S\s+\S+\s+)*-C\s+uid!=euid\s+-F\s+euid=0(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bexecve\b\S*\s+(?:-S\s+\S+\s+)*-C\s+gid!=egid\s+-F\s+egid=0(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238310r808489_rule" do
  title "The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bunlink\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\brmdir\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\bunlinkat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\brename\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b32\s+(?:-S\s+\S+\s+)*-S\s+\S*\brenameat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
  end
  if command('uname -i').stdout.strip == 'x86_64'
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bunlink\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\brmdir\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\bunlinkat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\brename\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+arch=b64\s+(?:-S\s+\S+\s+)*-S\s+\S*\brenameat\b\S*\s+(?:-S\s+\S+\s+)*-F\s+auid>=1000\s+-F\s+auid!=(?:4294967295|-1|unset)(?:\s+(?:-k\s+|-F\s+key=)[-\w]+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238315r654120_rule" do
  title "The Ubuntu operating system must generate audit records for the /var/log/wtmp file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/log\/wtmp(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/log\/wtmp\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238316r654123_rule" do
  title "The Ubuntu operating system must generate audit records for the /var/run/wtmp file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/run\/wtmp(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/run\/wtmp\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238317r654126_rule" do
  title "The Ubuntu operating system must generate audit records for the /var/log/btmp file."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/var\/log\/btmp(?:\s+-p\s+(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*))?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/var\/log\/btmp\s+-F\s+perm=(?:[rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238318r654129_rule" do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use modprobe command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/sbin\/modprobe(?:\s+-p\s+[rwa]*x[rwa]*)?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/sbin\/modprobe\s+-F\s+perm=[rwa]*x[rwa]*(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238319r654132_rule" do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the kmod command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/bin\/kmod(?:\s+-p\s+[rwa]*x[rwa]*)?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/bin\/kmod\s+-F\s+perm=[rwa]*x[rwa]*(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238320r654135_rule" do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the fdisk command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-w\s+\/bin\/fdisk(?:\s+-p\s+[rwa]*x[rwa]*)?(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\s*-a\s+(?:always,exit|exit,always)\s+-F\s+path=\/bin\/fdisk\s+-F\s+perm=[rwa]*x[rwa]*(?:\s+(?:-k\s+|-F\s+key=)\S+)*\s*$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238323r654144_rule" do
  title "The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and/or account types."
  desc  "
    Vulnerability Discussion: The Ubuntu operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.
    
    This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000054"
  tag nist: ["NIST SP 800-53", "3", "AC-10"]
  tag nist: ["NIST SP 800-53A", "1", "AC-10.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-10"]
  describe file("/etc/security/limits.conf") do
    its("content") { should match(/^\s*\*\s+hard\s+maxlogins\s+(10|[2-9])\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238325r654150_rule" do
  title "The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
  desc  "
    Vulnerability Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000803"
  tag nist: ["NIST SP 800-53", "3", "IA-7"]
  tag nist: ["NIST SP 800-53A", "1", "IA-7.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-7"]
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*ENCRYPT_METHOD\s+(\w*)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*ENCRYPT_METHOD\s+(\w*)\s*$/).flatten.each do |entry|
    describe entry do
      it { should eq "SHA512" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238330r654165_rule" do
  title "The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
  desc  "
    Vulnerability Discussion: Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.
    
    Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000795"
  tag nist: ["NIST SP 800-53", "3", "IA-4 e"]
  tag nist: ["NIST SP 800-53A", "1", "IA-4.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-4 e"]
  describe file("/etc/default/useradd") do
    its("content") { should match(/(?i)^\s*INACTIVE\s*=\s*(-?\d+)\s*$/) }
  end
  file("/etc/default/useradd").content.to_s.scan(/(?i)^\s*INACTIVE\s*=\s*(-?\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp > 0 }
    end
  end
  file("/etc/default/useradd").content.to_s.scan(/(?i)^\s*INACTIVE\s*=\s*(-?\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 35 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238333r654174_rule" do
  title "The Ubuntu operating system must be configured to use TCP syncookies."
  desc  "
    Vulnerability Discussion: DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.
    
    Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001095"
  tag nist: ["NIST SP 800-53", "3", "SC-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "SC-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-5 (2)"]
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net\.ipv4\.tcp_syncookies\s*=\s*1\s*$/) }
    end
    command('find /etc/sysctl.d -type f -name "*.conf"').stdout.split("\n").each do |file|
      describe file(file) do
        its("content") { should match(/^\s*net\.ipv4\.tcp_syncookies\s*=\s*1\s*$/) }
      end
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238337r654186_rule" do
  title "The Ubuntu operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
  desc  "
    Vulnerability Discussion: Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.
    
    Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001312"
  tag nist: ["NIST SP 800-53", "3", "SI-11 b"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 a"]
  describe command('find /var/log -perm /137 -type f -exec stat -c \"%n %a\" {} \;') do
    its("stdout") { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238338r654189_rule" do
  title "The Ubuntu operating system must configure the /var/log directory to be group-owned by syslog."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe command("stat -c \"%n %G\" /var/log | awk '{print $2}'") do
    its("stdout.strip") { should match(/^syslog$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238339r654192_rule" do
  title "The Ubuntu operating system must configure the /var/log directory to be owned by root."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe command("stat -c \"%n %U\" /var/log   | awk '{print $2}'") do
    its("stdout.strip") { should match(/^root$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238340r654195_rule" do
  title "The Ubuntu operating system must configure the /var/log directory to have mode 0750 or less permissive."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe file("/var/log") do
    it { should exist }
  end
  describe file("/var/log") do
    it { should_not be_writable.by "group" }
  end
  describe file("/var/log") do
    it { should_not be_executable.by "other" }
  end
  describe file("/var/log") do
    it { should_not be_readable.by "other" }
  end
  describe file("/var/log") do
    it { should_not be_writable.by "other" }
  end
  describe file("/var/log") do
    it { should_not be_setgid }
  end
  describe file("/var/log") do
    it { should_not be_sticky }
  end
  describe file("/var/log") do
    it { should_not be_setuid }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238341r654198_rule" do
  title "The Ubuntu operating system must configure the /var/log/syslog file to be group-owned by adm."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe command("stat -c \"%n %G\" /var/log/syslog | awk '{print $2}'") do
    its("stdout.strip") { should match(/^adm$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238342r654201_rule" do
  title "The Ubuntu operating system must configure /var/log/syslog file to be owned by syslog."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe command("stat -c \"%n %U\" /var/log/syslog  | awk '{print $2}'") do
    its("stdout.strip") { should match(/^syslog$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238343r654204_rule" do
  title "The Ubuntu operating system must configure /var/log/syslog file with mode 0640 or less permissive."
  desc  "
    Vulnerability Discussion: Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
    
    The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001314"
  tag nist: ["NIST SP 800-53", "3", "SI-11 c"]
  tag nist: ["NIST SP 800-53A", "1", "SI-11.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-11 b"]
  describe file("/var/log/syslog") do
    it { should exist }
  end
  describe file("/var/log/syslog") do
    it { should_not be_executable.by "group" }
  end
  describe file("/var/log/syslog") do
    it { should_not be_writable.by "group" }
  end
  describe file("/var/log/syslog") do
    it { should_not be_executable.by "other" }
  end
  describe file("/var/log/syslog") do
    it { should_not be_readable.by "other" }
  end
  describe file("/var/log/syslog") do
    it { should_not be_writable.by "other" }
  end
  describe file("/var/log/syslog") do
    it { should_not be_setgid }
  end
  describe file("/var/log/syslog") do
    it { should_not be_sticky }
  end
  describe file("/var/log/syslog") do
    it { should_not be_setuid }
  end
  describe file("/var/log/syslog") do
    it { should_not be_executable.by "owner" }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238354r654237_rule" do
  title "The Ubuntu operating system must have an application firewall installed in order to control remote access methods."
  desc  "
    Vulnerability Discussion: Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.
    
    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
    
    Ubuntu operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002314"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (1)"]
  describe package("ufw") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238357r654246_rule" do
  title "The Ubuntu operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second."
  desc  "
    Vulnerability Discussion: Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.
    
    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).
    
    Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-002046"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-8 (1) (b)"]
  describe file("/etc/chrony/chrony.conf") do
    its("content") { should match(/(?i)^\s*makestep\s+1\s+-1\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238359r654319_rule" do
  title "The Ubuntu operating system's Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."
  desc  "
    Vulnerability Discussion: Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
    
    Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.
    
    Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001749"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-5 (3)"]
  files = command('find /etc/apt/apt.conf.d -type f').stdout.split("\n")
  files.each do |file|
    describe.one do
      describe file(file) do
        its("content") { should_not match(/^\S+::AllowUnauthenticated\s*/) }
      end
      describe file(file) do
        its("content") { should match(/^\S+::AllowUnauthenticated\s+"false";$/) }
      end
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-238369r654282_rule" do
  title "The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution."
  desc  "
    Vulnerability Discussion: Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.
    
    Examples of attacks are buffer overflow attacks.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002824"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-16"]
  command('find /etc/sysctl.d/ -type f').stdout.split("\n").each do |file|
    describe file(file) do
      its("content") { should_not match(/^\s*kernel.randomize_va_space\s*=\s*(\S+)\s*$/) }
    end
  end
  describe file("/etc/sysctl.conf") do
    its("content") { should_not match(/^\s*kernel.randomize_va_space\s*=\s*(\S+)\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238370r654285_rule" do
  title "The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed."
  desc  "
    Vulnerability Discussion: Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002617"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-2 (6)"]
  describe file("/etc/apt/apt.conf.d/50unattended-upgrades") do
    its("content") { should match(/^\s*Unattended-Upgrade::Remove-Unused-Dependencies\s+"true"\s*;\s*$/) }
  end
  describe file("/etc/apt/apt.conf.d/50unattended-upgrades") do
    its("content") { should match(/^\s*Unattended-Upgrade::Remove-Unused-Kernel-Packages\s+"true"\s*;\s*$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238371r654288_rule" do
  title "The Ubuntu operating system must use a file integrity tool to verify correct operation of all security functions."
  desc  "
    Vulnerability Discussion: Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.
    
    This requirement applies to the Ubuntu operating system performing security function verification/testing and/or systems and environments that require this functionality.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002696"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-6 a"]
  describe package("aide") do
    it { should be_installed }
  end
end

control "xccdf_mil.disa.stig_rule_SV-238373r654294_rule" do
  title "The Ubuntu operating system must display the date and time of the last successful account logon upon logon."
  desc  "
    Vulnerability Discussion: Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe file("/etc/pam.d/login") do
    its("content") { should match(/^\s*session\s+required\s+pam_lastlog\.so\s+(?:\w+\s+)*showfailed\b\s*(?:\w+\b\s*)*\s*(?:#.*)?$/) }
  end
  describe file("/etc/pam.d/login") do
    its("content") { should_not match(/^\s*session\s+required\s+pam_lastlog\.so\s+(?:\w+\s+)*silent\b\s*(?:\w+\b\s*)*\s*(?:#.*)?$/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-251505r808512_rule" do
  title "The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver."
  desc  "
    Vulnerability Discussion: Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
    
    Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001958"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-3"]
  files = command("find /etc/modprobe.d -type f -regex .\\*/.\\*").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*install[ \t]+usb-storage[ \t]+\/bin\/true[ \t]*$/ } do
    it { should_not be_empty }
  end
  files = command("find /etc/modprobe.d -type f -regex .\\*/.\\*").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*blacklist[ \t]+usb-storage[ \t]*$/ } do
    it { should_not be_empty }
  end
end