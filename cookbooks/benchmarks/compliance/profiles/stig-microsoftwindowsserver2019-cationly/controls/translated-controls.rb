# encoding: UTF-8

control "xccdf_mil.disa.stig_rule_SV-205625r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Management - Security Group Management successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Security Group Management records events such as creating, deleting, or changing security groups, including changes in group members.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221
    
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
    describe audit_policy do
      its("Security Group Management") { should eq "Success" }
    end
    describe audit_policy do
      its("Security Group Management") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205626r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Management - User Account Management successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221
    
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
    describe audit_policy do
      its("User Account Management") { should eq "Success" }
    end
    describe audit_policy do
      its("User Account Management") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205627r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Management - User Account Management failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.
    
    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221
    
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
    describe audit_policy do
      its("User Account Management") { should eq "Failure" }
    end
    describe audit_policy do
      its("User Account Management") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205629r569188_rule" do
  title "Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less."
  desc  "
    Vulnerability Discussion: The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000044"
  tag nist: ["NIST SP 800-53", "3", "AC-7 a"]
  tag nist: ["NIST SP 800-53A", "1", "AC-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 a"]
  describe security_policy do
    its("LockoutBadCount") { should be <= 3 }
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205630r569188_rule" do
  title "Windows Server 2019 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."
  desc  "
    Vulnerability Discussion: The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to \"0\". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.
    
    Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000044"
  tag nist: ["NIST SP 800-53", "3", "AC-7 a"]
  tag nist: ["NIST SP 800-53A", "1", "AC-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 a"]
  tag cci: "CCI-002238"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 b"]
  describe security_policy do
    its("ResetLockoutCount") { should be >= 15 }
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205633r569188_rule" do
  title "Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."
  desc  "
    Vulnerability Discussion: Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.
    
    Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000029-GPOS-00010, SRG-OS-000031-GPOS-00012
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000056"
  tag nist: ["NIST SP 800-53", "3", "AC-11 b"]
  tag nist: ["NIST SP 800-53A", "1", "AC-11.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-11 b"]
  tag cci: "CCI-000057"
  tag nist: ["NIST SP 800-53", "3", "AC-11 a"]
  tag nist: ["NIST SP 800-53A", "1", "AC-11.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-11 a"]
  tag cci: "CCI-000060"
  tag nist: ["NIST SP 800-53", "3", "AC-11 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-11 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-11 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "InactivityTimeoutSecs" }
    its("InactivityTimeoutSecs") { should cmp <= 900 }
    its("InactivityTimeoutSecs") { should cmp > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205634r569188_rule" do
  title "Windows Server 2019 must be configured to audit logon successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.
    
    Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000067"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (1)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Logon") { should eq "Success" }
    end
    describe audit_policy do
      its("Logon") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205635r569188_rule" do
  title "Windows Server 2019 must be configured to audit logon failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.
    
    Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000067"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (1).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (1)"]
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Logon") { should eq "Failure" }
    end
    describe audit_policy do
      its("Logon") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205636r569188_rule" do
  title "Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."
  desc  "
    Vulnerability Discussion: Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.
    
    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000250-GPOS-00093
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000068"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  tag cci: "CCI-001453"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fEncryptRPCTraffic" }
    its("fEncryptRPCTraffic") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205637r569188_rule" do
  title "Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level."
  desc  "
    Vulnerability Discussion: Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting \"High Level\" will ensure encryption of Remote Desktop Services sessions in both directions.
    
    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000250-GPOS-00093
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000068"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  tag cci: "CCI-001453"
  tag nist: ["NIST SP 800-53", "3", "AC-17 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-17 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (2)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "MinEncryptionLevel" }
    its("MinEncryptionLevel") { should cmp == 3 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205638r569188_rule" do
  title "Windows Server 2019 command line data must be included in process creation events."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Enabling \"Include command line data for process creation events\" will record the command line information with the process creation events in the log. This can provide additional detail when malware has run on a system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000135"
  tag nist: ["NIST SP 800-53", "3", "AU-3 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3 (1).1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit") do
    it { should have_property "ProcessCreationIncludeCmdLine_Enabled" }
    its("ProcessCreationIncludeCmdLine_Enabled") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205639r569188_rule" do
  title "Windows Server 2019 PowerShell script block logging must be enabled."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000135"
  tag nist: ["NIST SP 800-53", "3", "AU-3 (1)"]
  tag nist: ["NIST SP 800-53A", "1", "AU-3 (1).1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-3 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    it { should have_property "EnableScriptBlockLogging" }
    its("EnableScriptBlockLogging") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205640r569188_rule" do
  title "Windows Server 2019 permissions for the Application event log must prevent access by non-privileged accounts."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Application event log may be susceptible to tampering if proper permissions are not applied.
    
    Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000162"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000163"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000164"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application") do
    it { should have_property "File" }
    its("File") { should_not match(/^%[Ss][Yy][Ss][Tt][Ee][Mm][Rr][Oo][Oo][Tt]%.*$/) }
  end
  file_path = registry_key({ hive: 'HKEY_LOCAL_MACHINE', key: 'SYSTEM\CurrentControlSet\Services\EventLog\Application'}).File
  file_permissions = powershell("(get-acl -path #{file_path}).access | ConvertTo-Json").stdout
  permissions = (file_permissions == "") ? [] : JSON.parse(file_permissions)
  permissions = [permissions] unless permissions.kind_of?(Array)
  permissions.each do |permission|
    describe.one do
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT SERVICE\\EventLog" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT AUTHORITY\\SYSTEM" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "BUILTIN\\Administrators" }
      end
    end
    describe permission["AccessControlType"] do
      it { should eq 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205641r569188_rule" do
  title "Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Security event log may disclose sensitive information or be susceptible to tampering if proper permissions are not applied.
    
    Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000162"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000163"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000164"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security") do
    it { should have_property "File" }
    its("File") { should_not match(/^%[Ss][Yy][Ss][Tt][Ee][Mm][Rr][Oo][Oo][Tt]%.*$/) }
  end
  file_path = registry_key({ hive: 'HKEY_LOCAL_MACHINE', key: 'SYSTEM\CurrentControlSet\Services\EventLog\Security'}).File
  file_permissions = powershell("(get-acl -path #{file_path}).access | ConvertTo-Json").stdout
  permissions = (file_permissions == "") ? [] : JSON.parse(file_permissions)
  permissions = [permissions] unless permissions.kind_of?(Array)
  permissions.each do |permission|
    describe.one do
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT SERVICE\\EventLog" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT AUTHORITY\\SYSTEM" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "BUILTIN\\Administrators" }
      end
    end
    describe permission["AccessControlType"] do
      it { should eq 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205642r569188_rule" do
  title "Windows Server 2019 permissions for the System event log must prevent access by non-privileged accounts."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The System event log may be susceptible to tampering if proper permissions are not applied.
    
    Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000162"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000163"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000164"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System") do
    it { should have_property "File" }
    its("File") { should_not match(/^%[Ss][Yy][Ss][Tt][Ee][Mm][Rr][Oo][Oo][Tt]%.*$/) }
  end
  file_path = registry_key({ hive: 'HKEY_LOCAL_MACHINE', key: 'SYSTEM\CurrentControlSet\Services\EventLog\System'}).File
  file_permissions = powershell("(get-acl -path #{file_path}).access | ConvertTo-Json").stdout
  permissions = (file_permissions == "") ? [] : JSON.parse(file_permissions)
  permissions = [permissions] unless permissions.kind_of?(Array)
  permissions.each do |permission|
    describe.one do
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT SERVICE\\EventLog" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "NT AUTHORITY\\SYSTEM" } 
      end
      describe permission["IdentityReference"]["Value"] do
        it { should eq "BUILTIN\\Administrators" }
      end
    end
    describe permission["AccessControlType"] do
      it { should eq 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205643r569188_rule" do
  title "Windows Server 2019 Manage auditing and security log user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Manage auditing and security log\" user right can manage the security log and change auditing configurations. This could be used to clear evidence of tampering.
    
    Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029, SRG-OS-000063-GPOS-00032, SRG-OS-000337-GPOS-00129
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000162"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000163"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000164"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-000171"
  tag nist: ["NIST SP 800-53", "3", "AU-12 b"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 b"]
  tag cci: "CCI-001914"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 (3)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeSecurityPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205644r569188_rule" do
  title "Windows Server 2019 must force audit policy subcategory settings to override audit policy category settings."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    This setting allows administrators to enable more precise auditing capabilities.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000169"
  tag nist: ["NIST SP 800-53", "3", "AU-12 a"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "SCENoApplyLegacyAuditPolicy" }
    its("SCENoApplyLegacyAuditPolicy") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205648r819704_rule" do
  title "Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store."
  desc  "
    Vulnerability Discussion: To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs. The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.
    
    Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000185"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (a)"]
  tag cci: "CCI-002440"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-12"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
  end
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
  end
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\4ECB5CC3095670454DA1CBD410FC921F46B8564B") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\4ECB5CC3095670454DA1CBD410FC921F46B8564B") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\4ECB5CC3095670454DA1CBD410FC921F46B8564B") do
      it { should exist }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205649r819707_rule" do
  title "Windows Server 2019 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems."
  desc  "
    Vulnerability Discussion: To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.
    
    Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000185"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (a)"]
  tag cci: "CCI-002440"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-12"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\49CBE933151872E17C8EAE7F0ABA97FB610F6477") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed\\Certificates\\49CBE933151872E17C8EAE7F0ABA97FB610F6477") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\49CBE933151872E17C8EAE7F0ABA97FB610F6477") do
      it { should exist }
    end
  end
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\AC06108CA348CC03B53795C64BF84403C1DBD341") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed\\Certificates\\AC06108CA348CC03B53795C64BF84403C1DBD341") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\AC06108CA348CC03B53795C64BF84403C1DBD341") do
      it { should exist }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205650r573797_rule" do
  title "Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems."
  desc  "
    Vulnerability Discussion: To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.
    
    Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000185"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (a)"]
  tag cci: "CCI-002470"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-23 (5)"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed\\Certificates\\AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9") do
      it { should exist }
    end
  end
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\929BF3196896994C0A201DF4A5B71F603FEFBF2E") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Disallowed\\Certificates\\929BF3196896994C0A201DF4A5B71F603FEFBF2E") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates\\929BF3196896994C0A201DF4A5B71F603FEFBF2E") do
      it { should exist }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205651r569188_rule" do
  title "Windows Server 2019 users must be required to enter a password to access private keys stored on the computer."
  desc  "
    Vulnerability Discussion: If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.
    
    The cornerstone of the PKI is the private key used to encrypt or digitally sign information.
    
    If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.
    
    Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000186"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (2)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (2).1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (2) (b)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography") do
    it { should have_property "ForceKeyProtection" }
    its("ForceKeyProtection") { should cmp == 2 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205652r569188_rule" do
  title "Windows Server 2019 must have the built-in Windows password complexity policy enabled."
  desc  "
    Vulnerability Discussion: The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least three of the four types of characters (numbers, uppercase and lowercase letters, and special characters) and prevents the inclusion of user names or parts of user names.
    
    Satisfies: SRG-OS-000069-GPOS-00037, SRG-OS-000070-GPOS-00038, SRG-OS-000071-GPOS-00039, SRG-OS-000266-GPOS-00101
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000192"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  tag cci: "CCI-000193"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  tag cci: "CCI-000194"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  tag cci: "CCI-001619"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe security_policy do
    its("PasswordComplexity") { should eq 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205655r569188_rule" do
  title "Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."
  desc  "
    Vulnerability Discussion: Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication. Sending plain-text passwords across the network when authenticating to an SMB server reduces the overall security of the environment. Check with the vendor of the SMB server to determine if there is a way to support encrypted password authentication.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000197"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (c)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (c)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "EnablePlainTextPassword" }
    its("EnablePlainTextPassword") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205656r569188_rule" do
  title "Windows Server 2019 minimum password age must be configured to at least one day."
  desc  "
    Vulnerability Discussion: Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000198"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (d)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (d)"]
  describe security_policy do
    its("MinimumPasswordAge") { should be >= 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205659r569188_rule" do
  title "Windows Server 2019 maximum password age must be configured to 60 days or less."
  desc  "
    Vulnerability Discussion: The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000199"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (d)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (d)"]
  describe security_policy do
    its("MaximumPasswordAge") { should be <= 60 }
  end
  describe security_policy do
    its("MaximumPasswordAge") { should be > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205660r569188_rule" do
  title "Windows Server 2019 password history must be configured to 24 passwords remembered."
  desc  "
    Vulnerability Discussion: A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is \"24\" for Windows domain systems. DoD has decided this is the appropriate value for all Windows systems.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000200"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (e)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (v)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (e)"]
  describe security_policy do
    its("PasswordHistorySize") { should be >= 24 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205662r569188_rule" do
  title "Windows Server 2019 minimum password length must be configured to 14 characters."
  desc  "
    Vulnerability Discussion: Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000205"
  tag nist: ["NIST SP 800-53", "3", "IA-5 (1) (a)"]
  tag nist: ["NIST SP 800-53A", "1", "IA-5 (1).1 (i)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-5 (1) (a)"]
  describe security_policy do
    its("MinimumPasswordLength") { should be >= 14 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205665r569188_rule" do
  title "Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and\nEnterprise Domain Controllers groups on domain controllers."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Access this computer from the network\" right may access resources on the system, and this right must be limited to those requiring it.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    allowed_principals = ['S-1-5-11'] + ['S-1-5-9'] + ['S-1-5-32-544']
    describe security_policy.SeNetworkLogonRight - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205666r569188_rule" do
  title "Windows Server 2019 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Allow log on through Remote Desktop Services\" user right can access a system through Remote Desktop.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    allowed_principals = ['S-1-5-32-544']
    describe security_policy.SeRemoteInteractiveLogonRight - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205667r569188_rule" do
  title "Windows Server 2019 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny access to this computer from the network\" user right defines the accounts that are prevented from logging on from the network.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    allowed_principals = ['S-1-5-32-544']
    describe security_policy.SeEnableDelegationPrivilege - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205668r569188_rule" do
  title "Windows Server 2019 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on as a batch job\" user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.
    
    The Guests group must be assigned to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    security_principals = ['S-1-5-32-546']
    describe security_policy.SeDenyBatchLogonRight & security_principals do
      it { should eq security_principals }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205669r569188_rule" do
  title "Windows Server 2019 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on as a service\" user right defines accounts that are denied logon as a service.
    
    Incorrect configurations could prevent services from starting and result in a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe security_policy.SeDenyServiceLogonRight do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205670r569188_rule" do
  title "Windows Server 2019 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on locally\" user right defines accounts that are prevented from logging on interactively.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    security_principals = ['S-1-5-32-546']
    describe security_policy.SeDenyInteractiveLogonRight & security_principals do
      it { should eq security_principals }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205671r569188_rule" do
  title "Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Access this computer from the network\" user right may access resources on the system, and this right must be limited to those requiring it.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role= wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems') { domain_role == [2] || domain_role == [3] }
    allowed_principals = ['S-1-5-32-544'] + ['S-1-5-11']
    describe security_policy.SeNetworkLogonRight - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205672r569188_rule" do
  title "Windows Server 2019 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny access to this computer from the network\" user right defines the accounts that are prevented from logging on from the network.
    
    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.
    
    Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  standalone_server = 2
  member_server = 3
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems') { domain_role == [2] || domain_role == [3] }
  if domain_role.include?(standalone_server)
    describe security_policy do
      its("SeDenyNetworkLogonRight") { should include 'S-1-5-32-546' }
    end
  else
    machine_sid = powershell('"{0}-512" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid').stdout.strip.gsub(/^S-1-5-21-/, '').gsub(/-[0-9]+$/, '')
    security_principals = ['S-1-5-32-546', "S-1-5-21-#{machine_sid}-512", "S-1-5-21-#{machine_sid}-519"].sort
    describe security_policy.SeDenyNetworkLogonRight.sort & security_principals do
      it { should cmp security_principals }
    end
    describe.one do
      describe security_policy do
        its('SeDenyNetworkLogonRight') { should include 'S-1-5-113' }
      end
      describe security_policy do
        its('SeDenyNetworkLogonRight') { should include 'S-1-5-114' }
      end
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205673r569188_rule" do
  title "Windows Server 2019 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on as a batch job\" user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.
    
    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.
    
    The Guests group must be assigned to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems') { domain_role == [2] || domain_role == [3] }
    standalone_server = 2
    member_server = 3
    # when standalone_server
    if domain_role.include?(standalone_server)
      describe security_policy do
        its("SeDenyBatchLogonRight") { should include 'S-1-5-32-546' }
      end
    # when member_server
    else
      machine_sid = powershell('"{0}-512" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid').stdout.strip.gsub(/^S-1-5-21-/, '').gsub(/-[0-9]+$/, '')
      domain_admins_security_principal = ["S-1-5-21-#{machine_sid}-512"]
      enterprise_admins_security_principal = ["S-1-5-21-#{machine_sid}-519"]
      required_principals = domain_admins_security_principal + enterprise_admins_security_principal
      describe security_policy.SeDenyBatchLogonRight & required_principals do
        it { should eq required_principals }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205674r819709_rule" do
  title "Windows Server 2019 \"Deny log on as a service\" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on as a service\" user right defines accounts that are denied logon as a service.
    
    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.
    
    Incorrect configurations could prevent services from starting and result in a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers') { domain_role == [3] }
    machine_sid = powershell('"{0}-512" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid').stdout.strip.gsub(/^S-1-5-21-/, '').gsub(/-[0-9]+$/, '')
    domain_admins_security_principal = ["S-1-5-21-#{machine_sid}-512"]
    enterprise_admins_security_principal = ["S-1-5-21-#{machine_sid}-519"]
    required_principals = domain_admins_security_principal + enterprise_admins_security_principal
    describe security_policy.SeDenyServiceLogonRight & required_principals do
      it { should eq required_principals }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205675r569188_rule" do
  title "Windows Server 2019 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on locally\" user right defines accounts that are prevented from logging on interactively.
    
    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems') { domain_role == [2] || domain_role == [3] }
    standalone_server = 2
    member_server = 3
    # when standalone_server
    if domain_role.include?(standalone_server)
      describe security_policy do
        its("SeDenyInteractiveLogonRight") { should include 'S-1-5-32-546' }
      end
    # when member_server
    elsif domain_role.include?(member_server)
      machine_sid = powershell('"{0}-512" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid').stdout.strip.gsub(/^S-1-5-21-/, '').gsub(/-[0-9]+$/, '')
      domain_admins_security_principal = ["S-1-5-21-#{machine_sid}-512"]
      enterprise_admins_security_principal = ["S-1-5-21-#{machine_sid}-519"]
      required_principals = domain_admins_security_principal + enterprise_admins_security_principal + ['S-1-5-32-546']
      describe security_policy.SeDenyInteractiveLogonRight & required_principals do
        it { should eq required_principals }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205676r569188_rule" do
  title "Windows Server 2019 Allow log on locally user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Allow log on locally\" user right can log on interactively to a system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000213"
  tag nist: ["NIST SP 800-53", "3", "AC-3"]
  tag nist: ["NIST SP 800-53A", "1", "AC-3.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-3"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeInteractiveLogonRight - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205678r569188_rule" do
  title "Windows Server 2019 must not have the Fax Server role installed."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe.one do
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='fax'"}) do
      its("startmode") { should be_nil }
    end
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='fax'"}) do
      its("startmode") { should cmp "Disabled" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205679r569188_rule" do
  title "Windows Server 2019 must not have the Peer Name Resolution Protocol installed."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe.one do
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='pnrpsvc'"}) do
      its("startmode") { should be_nil }
    end
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='pnrpsvc'"}) do
      its("startmode") { should cmp "Disabled" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205680r569188_rule" do
  title "Windows Server 2019 must not have Simple TCP/IP Services installed."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe.one do
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='simptcp'"}) do
      its("startmode") { should be_nil }
    end
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='simptcp'"}) do
      its("startmode") { should cmp "Disabled" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205681r569188_rule" do
  title "Windows Server 2019 must not have the TFTP Client installed."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT id FROM win32_serverfeature"}) do
    its("id") { should_not include 58 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205682r819711_rule" do
  title "Windows Server 2019 must not have the Server Message Block (SMB) v1 protocol installed."
  desc  "
    Vulnerability Discussion: SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe.one do
    describe powershell("Get-WindowsFeature -Name FS-SMB1 |  Format-Table InstallState -HideTableHeaders").stdout.strip.upcase do
      it { should eq "AVAILABLE" }
    end
    describe powershell("Get-WindowsFeature -Name FS-SMB1 |  Format-Table InstallState -HideTableHeaders").stdout.strip.upcase do
      it { should eq "REMOVED" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205683r569188_rule" do
  title "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server."
  desc  "
    Vulnerability Discussion: SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters") do
    it { should have_property "SMB1" }
    its("SMB1") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205684r569188_rule" do
  title "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client."
  desc  "
    Vulnerability Discussion: SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10") do
    it { should have_property "Start" }
    its("Start") { should cmp == 4 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205685r569188_rule" do
  title "Windows Server 2019 must not have Windows PowerShell 2.0 installed."
  desc  "
    Vulnerability Discussion: Windows PowerShell 5.x added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.x script block logging feature.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT id FROM win32_serverfeature"}) do
    its("id") { should_not include 411 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205686r569188_rule" do
  title "Windows Server 2019 must prevent the display of slide shows on the lock screen."
  desc  "
    Vulnerability Discussion: Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205687r569188_rule" do
  title "Windows Server 2019 must have WDigest Authentication disabled."
  desc  "
    Vulnerability Discussion: When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2019. This setting ensures this is enforced.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest") do
    it { should have_property "UseLogonCredential" }
    its("UseLogonCredential") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205688r569188_rule" do
  title "Windows Server 2019 downloading print driver packages over HTTP must be turned off."
  desc  "
    Vulnerability Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.
    
    This setting prevents the computer from downloading print driver packages over HTTP.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers") do
    it { should have_property "DisableWebPnPDownload" }
    its("DisableWebPnPDownload") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205689r569188_rule" do
  title "Windows Server 2019 printing over HTTP must be turned off."
  desc  "
    Vulnerability Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.
    
    This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers") do
    it { should have_property "DisableHTTPPrinting" }
    its("DisableHTTPPrinting") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205690r569188_rule" do
  title "Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen."
  desc  "
    Vulnerability Discussion: Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontDisplayNetworkSelectionUI" }
    its("DontDisplayNetworkSelectionUI") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205691r569188_rule" do
  title "Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
  desc  "
    Vulnerability Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.
    
    This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat") do
    it { should have_property "DisableInventory" }
    its("DisableInventory") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205692r569188_rule" do
  title "Windows Server 2019 Windows Defender SmartScreen must be enabled."
  desc  "
    Vulnerability Discussion: Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen can block potentially malicious programs or warn users.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnableSmartScreen" }
    its("EnableSmartScreen") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205693r569188_rule" do
  title "Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP."
  desc  "
    Vulnerability Discussion: Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
      it { should_not have_property "AllowBasicAuthInClear" }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
      it { should have_property "AllowBasicAuthInClear" }
      its("AllowBasicAuthInClear") { should cmp == 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205694r569188_rule" do
  title "Windows Server 2019 must prevent Indexing of encrypted files."
  desc  "
    Vulnerability Discussion: Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowIndexingEncryptedStoresOrItems" }
    its("AllowIndexingEncryptedStoresOrItems") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205696r569188_rule" do
  title "Windows Server 2019 local users on domain-joined member servers must not be enumerated."
  desc  "
    Vulnerability Discussion: The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000381"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 a"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers') { domain_role == [3] }
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
      it { should have_property "EnumerateLocalUsers" }
      its("EnumerateLocalUsers") { should cmp == 0 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205697r569188_rule" do
  title "Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000382"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 b"]
  describe.one do
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='ftpsvc'"}) do
      its("startmode") { should be_nil }
    end
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='ftpsvc'"}) do
      its("startmode") { should cmp "Disabled" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205698r569188_rule" do
  title "Windows Server 2019 must not have the Telnet Client installed."
  desc  "
    Vulnerability Discussion: Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000382"
  tag nist: ["NIST SP 800-53", "3", "CM-7"]
  tag nist: ["NIST SP 800-53A", "1", "CM-7.1 (iii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-7 b"]
  describe.one do
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT InstallState FROM Win32_OptionalFeature WHERE name='telnetclient'"}) do
      its("InstallState") { should be_nil }
    end
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT InstallState FROM Win32_OptionalFeature WHERE name='telnetclient'"}) do
      its("installstate") { should_not cmp "1" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205702r569188_rule" do
  title "Windows Server 2019 Kerberos user logon restrictions must be enforced."
  desc  "
    Vulnerability Discussion: This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the target computer. The policy is enabled by default, which is the most secure setting for validating that access to target resources is not circumvented.
    
    Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001941"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (8)"]
  tag cci: "CCI-001942"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT setting FROM RSOP_SecuritySettingBoolean WHERE KeyName='TicketValidateClient'"}) do
      its("setting") { should cmp "true" }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205703r569188_rule" do
  title "Windows Server 2019 Kerberos service ticket maximum lifetime must be limited to 600 minutes or less."
  desc  "
    Vulnerability Discussion: This setting determines the maximum amount of time (in minutes) that a granted session ticket can be used to access a particular service. Session tickets are used only to authenticate new connections with servers. Ongoing operations are not interrupted if the session ticket used to authenticate the connection expires during the connection.
    
    Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001941"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (8)"]
  tag cci: "CCI-001942"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT setting FROM RSOP_SecuritySettingNumeric WHERE KeyName='MaxServiceAge'"}) do
      its("setting") { should_not cmp -1 }
      its("setting") { should cmp <= 600 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205704r569188_rule" do
  title "Windows Server 2019 Kerberos user ticket lifetime must be limited to 10 hours or less."
  desc  "
    Vulnerability Discussion: In Kerberos, there are two types of tickets: Ticket Granting Tickets (TGTs) and Service Tickets. Kerberos tickets have a limited lifetime so the time an attacker has to implement an attack is limited. This policy controls how long TGTs can be renewed. With Kerberos, the user's initial authentication to the domain controller results in a TGT, which is then used to request Service Tickets to resources. Upon startup, each computer gets a TGT before requesting a service ticket to the domain controller and any other computers it needs to access. For services that start up under a specified user account, users must always get a TGT first and then get Service Tickets to all computers and services accessed.
    
    Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001941"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (8)"]
  tag cci: "CCI-001942"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT setting FROM RSOP_SecuritySettingNumeric WHERE KeyName='MaxTicketAge'"}) do
      its("setting") { should_not cmp -1 }
      its("setting") { should cmp <= 10 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205705r569188_rule" do
  title "Windows Server 2019 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less."
  desc  "
    Vulnerability Discussion: This setting determines the period of time (in days) during which a user's Ticket Granting Ticket (TGT) may be renewed. This security configuration limits the amount of time an attacker has to crack the TGT and gain access.
    
    Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001941"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (8)"]
  tag cci: "CCI-001942"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT setting FROM RSOP_SecuritySettingNumeric WHERE KeyName='MaxRenewAge'"}) do
      its("setting") { should cmp <= 7 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205706r569188_rule" do
  title "Windows Server 2019 computer clock synchronization tolerance must be limited to five minutes or less."
  desc  "
    Vulnerability Discussion: This setting determines the maximum time difference (in minutes) that Kerberos will tolerate between the time on a client's clock and the time on a server's clock while still considering the two clocks synchronous. In order to prevent replay attacks, Kerberos uses timestamps as part of its protocol definition. For timestamps to work properly, the clocks of the client and the server need to be in sync as much as possible.
    
    Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001941"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (8)"]
  tag cci: "CCI-001942"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-2 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT setting FROM RSOP_SecuritySettingNumeric WHERE KeyName='MaxClockSkew'"}) do
      its("setting") { should cmp <= 5 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205708r569188_rule" do
  title "Windows Server 2019 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."
  desc  "
    Vulnerability Discussion: Certain encryption types are no longer considered secure. The DES and RC4 encryption suites must not be used for Kerberos encryption.
    
    Note: Organizations with domain controllers running earlier versions of Windows where RC4 encryption is enabled, selecting \"The other domain supports Kerberos AES Encryption\" on domain trusts, may be required to allow client communication across the trust relationship.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000803"
  tag nist: ["NIST SP 800-53", "3", "IA-7"]
  tag nist: ["NIST SP 800-53A", "1", "IA-7.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-7"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters") do
    it { should have_property "SupportedEncryptionTypes" }
    its("SupportedEncryptionTypes") { should cmp == 2147483640 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205709r569188_rule" do
  title "Windows Server 2019 must have the built-in guest account disabled."
  desc  "
    Vulnerability Discussion: A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000804"
  tag nist: ["NIST SP 800-53", "3", "IA-8"]
  tag nist: ["NIST SP 800-53A", "1", "IA-8.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-8"]
  machine_sid = powershell('"{0}-500" -f ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()').stdout.strip.gsub(/^S-[0-9]*-[0-9]*-[0-9]*-/, '').gsub(/-[0-9]+$/, '')
  user_sid = "S-1-5-21-#{machine_sid}-501"
  describe powershell("Get-LocalUser -SID '#{user_sid}' | Format-Table Enabled -HideTableHeaders").stdout.strip.upcase do
    it { should eq "FALSE" }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205712r569188_rule" do
  title "Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication."
  desc  "
    Vulnerability Discussion: Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000877"
  tag nist: ["NIST SP 800-53", "3", "MA-4 c"]
  tag nist: ["NIST SP 800-53A", "1", "MA-4.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 c"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowDigest" }
    its("AllowDigest") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205714r569188_rule" do
  title "Windows Server 2019 administrator accounts must not be enumerated during elevation."
  desc  "
    Vulnerability Discussion: Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI") do
    it { should have_property "EnumerateAdministrators" }
    its("EnumerateAdministrators") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205715r569188_rule" do
  title "Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."
  desc  "
    Vulnerability Discussion: A compromised local administrator account can provide means for an attacker to move laterally between domain systems.
    
    With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers') { domain_role == [3] }
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "LocalAccountTokenFilterPolicy" }
      its("LocalAccountTokenFilterPolicy") { should cmp == 0 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205716r569188_rule" do
  title "Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableUIADesktopToggle" }
    its("EnableUIADesktopToggle") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205717r569188_rule" do
  title "Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "ConsentPromptBehaviorAdmin" }
      its("ConsentPromptBehaviorAdmin") { should cmp == 2 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "ConsentPromptBehaviorAdmin" }
      its("ConsentPromptBehaviorAdmin") { should cmp == 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205718r569188_rule" do
  title "Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting requires Windows to respond to application installation requests by prompting for credentials.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableInstallerDetection" }
    its("EnableInstallerDetection") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205719r569188_rule" do
  title "Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations."
  desc  "
    Vulnerability Discussion: UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\\System32 folders, to run with elevated privileges.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableSecureUIAPaths" }
    its("EnableSecureUIAPaths") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205720r569188_rule" do
  title "Windows Server 2019 User Account Control (UAC) must virtualize file and registry write failures to per-user locations."
  desc  "
    Vulnerability Discussion: UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001084"
  tag nist: ["NIST SP 800-53", "3", "SC-3"]
  tag nist: ["NIST SP 800-53A", "1", "SC-3.1 (ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-3"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableVirtualization" }
    its("EnableVirtualization") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205722r569188_rule" do
  title "Windows Server 2019 Remote Desktop Services must prevent drive redirection."
  desc  "
    Vulnerability Discussion: Preventing users from sharing the local drives on their client computers with Remote Session Hosts that they access helps reduce possible exposure of sensitive data.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001090"
  tag nist: ["NIST SP 800-53", "3", "SC-4"]
  tag nist: ["NIST SP 800-53A", "1", "SC-4.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-4"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fDisableCdm" }
    its("fDisableCdm") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205729r569188_rule" do
  title "Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Account Lockout events can be used to identify potentially malicious logon attempts.
    
    Satisfies: SRG-OS-000240-GPOS-00090, SRG-OS-000470-GPOS-00214
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe audit_policy do
      its("Account Lockout") { should eq "Success" }
    end
    describe audit_policy do
      its("Account Lockout") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205730r569188_rule" do
  title "Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Account Lockout events can be used to identify potentially malicious logon attempts.
    
    Satisfies: SRG-OS-000240-GPOS-00090, SRG-OS-000470-GPOS-00214
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-001404"
  tag nist: ["NIST SP 800-53", "3", "AC-2 (4)"]
  tag nist: ["NIST SP 800-53A", "1", "AC-2 (4).1 (i and ii)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-2 (4)"]
  describe.one do
    describe audit_policy do
      its("Account Lockout") { should eq "Failure" }
    end
    describe audit_policy do
      its("Account Lockout") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205731r569188_rule" do
  title "Windows Server 2019 Event Viewer must be protected from unauthorized modification and deletion."
  desc  "
    Vulnerability Discussion: Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.
    
    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification or deletion of audit tools.
    
    Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001494"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  tag cci: "CCI-001495"
  tag nist: ["NIST SP 800-53", "3", "AU-9"]
  tag nist: ["NIST SP 800-53A", "1", "AU-9.1"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-9"]
  sysroot = registry_key({ hive: 'HKEY_LOCAL_MACHINE', key: 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'}).SystemRoot
  unauthorized_modify_sids = security_descriptor("#{sysroot}\\System32\\Eventvwr.exe").Modify - ['S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464']
  describe unauthorized_modify_sids do
    it { should be_empty }
  end
  sysroot = registry_key({ hive: 'HKEY_LOCAL_MACHINE', key: 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'}).SystemRoot
  unauthorized_fullcontrol_sids = security_descriptor("#{sysroot}\\System32\\Eventvwr.exe").FullControl - ['S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464']
  describe unauthorized_fullcontrol_sids do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205732r569188_rule" do
  title "Windows Server 2019 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on through Remote Desktop Services\" user right defines the accounts that are prevented from logging on using Remote Desktop Services.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002314"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (1)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    security_principals = ['S-1-5-32-546']
    describe security_policy.SeDenyRemoteInteractiveLogonRight & security_principals do
      it { should eq security_principals }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205733r569188_rule" do
  title "Windows Server 2019 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Deny log on through Remote Desktop Services\" user right defines the accounts that are prevented from logging on using Remote Desktop Services.
    
    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.
    
    Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.
    
    The Guests group must be assigned this right to prevent unauthenticated access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002314"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-17 (1)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems.') { domain_role == [2] || domain_role == [3] }
    standalone_server = 2
    member_server = 3
    # when standalone_server
    if domain_role.include?(standalone_server)
      describe security_policy do
        its("SeDenyRemoteInteractiveLogonRight") { should include 'S-1-5-32-546' }
      end
    # when member_server
    elsif domain_role.include?(member_server)
      machine_sid = powershell('"{0}-512" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid').stdout.strip.gsub(/^S-1-5-21-/, '').gsub(/-[0-9]+$/, '')
      required_principals = ['S-1-5-32-546']
      domain_admins_security_principal = ["S-1-5-21-#{machine_sid}-512"]
      enterprise_admins_security_principal = ["S-1-5-21-#{machine_sid}-519"]
      required_principals += domain_admins_security_principal + enterprise_admins_security_principal + ['S-1-5-113']
      describe security_policy.SeDenyRemoteInteractiveLogonRight & required_principals do
        it { should eq required_principals.sort }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205744r569188_rule" do
  title "Windows Server 2019 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Add workstations to domain\" right may add computers to a domain. This could result in unapproved or incorrectly configured systems being added to a domain.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    allowed_principals = ['S-1-5-32-544']
    describe security_policy.SeMachineAccountPrivilege - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205745r569188_rule" do
  title "Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Enable computer and user accounts to be trusted for delegation\" user right allows the \"Trusted for Delegation\" setting to be changed. This could allow unauthorized users to impersonate other users.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    allowed_principals = ['S-1-5-32-544']
    describe security_policy.SeEnableDelegationPrivilege - allowed_principals do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205747r569188_rule" do
  title "Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems."
  desc  "
    Vulnerability Discussion: The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems.') { domain_role == [2] || domain_role == [3] }
    describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
      it { should have_property "RestrictRemoteSAM" }
      its("RestrictRemoteSAM") { should eq "O:BAG:BAD:(A;;RC;;;BA)" }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205748r569188_rule" do
  title "Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone systems."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Enable computer and user accounts to be trusted for delegation\" user right allows the \"Trusted for Delegation\" setting to be changed. This could allow unauthorized users to impersonate other users.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems.') { domain_role == [2] || domain_role == [3] }
    describe security_policy.SeEnableDelegationPrivilege do
      it { should be_empty }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205749r569188_rule" do
  title "Windows Server 2019 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Access Credential Manager as a trusted caller\" user right may be able to retrieve the credentials of other accounts from Credential Manager.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  describe security_policy.SeTrustedCredManAccessPrivilege do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205751r569188_rule" do
  title "Windows Server 2019 Back up files and directories user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Back up files and directories\" user right can circumvent file and directory permissions and could allow access to sensitive data.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeBackupPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205752r569188_rule" do
  title "Windows Server 2019 Create a pagefile user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Create a pagefile\" user right can change the size of a pagefile, which could affect system performance.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeCreatePagefilePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205754r569188_rule" do
  title "Windows Server 2019 Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Create global objects\" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544'] + ['S-1-5-19'] + ['S-1-5-20'] + ['S-1-5-6']
  describe security_policy.SeCreateGlobalPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205755r569188_rule" do
  title "Windows Server 2019 Create permanent shared objects user right must not be assigned to any groups or accounts."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Create permanent shared objects\" user right could expose sensitive data by creating shared objects.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  describe security_policy.SeCreatePermanentPrivilege do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205756r569188_rule" do
  title "Windows Server 2019 Create symbolic links user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Create symbolic links\" user right can create pointers to other objects, which could expose the system to attack.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  if wmi({:namespace=>"root\\cimv2", :query=>"SELECT name FROM Win32_ServerFeature WHERE ID = 20"}).name == ["Hyper-V"]
    allowed_principals += ['S-1-5-83-0']
  end
  describe security_policy.SeCreateSymbolicLinkPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205758r569188_rule" do
  title "Windows Server 2019 Force shutdown from a remote system user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Force shutdown from a remote system\" user right can remotely shut down a system, which could result in a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeRemoteShutdownPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205759r569188_rule" do
  title "Windows Server 2019 Generate security audits user right must only be assigned to Local Service and Network Service."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Generate security audits\" user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-19'] + ['S-1-5-20']
  describe security_policy.SeAuditPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205760r569188_rule" do
  title "Windows Server 2019 Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Impersonate a client after authentication\" user right allows a program to impersonate another user or account to run on their behalf. An attacker could use this to elevate privileges.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544'] + ['S-1-5-19'] + ['S-1-5-20'] + ['S-1-5-6']
  describe security_policy.SeImpersonatePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205761r569188_rule" do
  title "Windows Server 2019 Increase scheduling priority: user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Increase scheduling priority\" user right can change a scheduling priority, causing performance issues or a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeIncreaseBasePriorityPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205762r569188_rule" do
  title "Windows Server 2019 Load and unload device drivers user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Load and unload device drivers\" user right allows a user to load device drivers dynamically on a system. This could be used by an attacker to install malicious code.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeLoadDriverPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205763r569188_rule" do
  title "Windows Server 2019 Lock pages in memory user right must not be assigned to any groups or accounts."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    The \"Lock pages in memory\" user right allows physical memory to be assigned to processes, which could cause performance issues or a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  describe security_policy.SeLockMemoryPrivilege do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205764r569188_rule" do
  title "Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Modify firmware environment values\" user right can change hardware configuration environment variables. This could result in hardware failures or a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeSystemEnvironmentPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205765r569188_rule" do
  title "Windows Server 2019 Perform volume maintenance tasks user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Perform volume maintenance tasks\" user right can manage volume and disk configurations. This could be used to delete volumes, resulting in data loss or a denial of service.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeManageVolumePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205766r569188_rule" do
  title "Windows Server 2019 Profile single process user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Profile single process\" user right can monitor non-system processes performance. An attacker could use this to identify processes to attack.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeProfileSingleProcessPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205767r569188_rule" do
  title "Windows Server 2019 Restore files and directories user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Restore files and directories\" user right can circumvent file and directory permissions and could allow access to sensitive data. It could also be used to overwrite more current data.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeRestorePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205768r569188_rule" do
  title "Windows Server 2019 Take ownership of files or other objects user right must only be assigned to the Administrators group."
  desc  "
    Vulnerability Discussion: Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    
    Accounts with the \"Take ownership of files or other objects\" user right can take ownership of objects and make changes.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002235"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (10)"]
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeTakeOwnershipPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205769r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Management - Other Account Management Events successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Other Account Management Events records events such as the access of a password hash or the Password Policy Checking API being called.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Other Account Management Events") { should eq "Success" }
    end
    describe audit_policy do
      its("Other Account Management Events") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205770r569188_rule" do
  title "Windows Server 2019 must be configured to audit Detailed Tracking - Process Creation successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Process Creation records events related to the creation of a process and the source.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Process Creation") { should eq "Success" }
    end
    describe audit_policy do
      its("Process Creation") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205771r569188_rule" do
  title "Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Policy Change records events related to changes in audit policy.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Audit Policy Change") { should eq "Success" }
    end
    describe audit_policy do
      its("Audit Policy Change") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205772r569188_rule" do
  title "Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Policy Change records events related to changes in audit policy.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Audit Policy Change") { should eq "Failure" }
    end
    describe audit_policy do
      its("Audit Policy Change") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205773r569188_rule" do
  title "Windows Server 2019 must be configured to audit Policy Change - Authentication Policy Change successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Authentication Policy Change records events related to changes in authentication policy, including Kerberos policy and Trust changes.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Authentication Policy Change") { should eq "Success" }
    end
    describe audit_policy do
      its("Authentication Policy Change") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205774r569188_rule" do
  title "Windows Server 2019 must be configured to audit Policy Change - Authorization Policy Change successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Authorization Policy Change records events related to changes in user rights, such as \"Create a token object\".
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Authorization Policy Change") { should eq "Success" }
    end
    describe audit_policy do
      its("Authorization Policy Change") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205775r569188_rule" do
  title "Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Sensitive Privilege Use records events related to use of sensitive privileges, such as \"Act as part of the operating system\" or \"Debug programs\".
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Sensitive Privilege Use") { should eq "Success" }
    end
    describe audit_policy do
      its("Sensitive Privilege Use") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205776r569188_rule" do
  title "Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Sensitive Privilege Use records events related to use of sensitive privileges, such as \"Act as part of the operating system\" or \"Debug programs\".
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Sensitive Privilege Use") { should eq "Failure" }
    end
    describe audit_policy do
      its("Sensitive Privilege Use") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205777r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - IPsec Driver successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    IPsec Driver records events related to the IPsec Driver, such as dropped packets.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("IPsec Driver") { should eq "Success" }
    end
    describe audit_policy do
      its("IPsec Driver") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205778r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - IPsec Driver failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    IPsec Driver records events related to the IPsec Driver, such as dropped packets.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("IPsec Driver") { should eq "Failure" }
    end
    describe audit_policy do
      its("IPsec Driver") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205779r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - Other System Events successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Other System Events") { should eq "Success" }
    end
    describe audit_policy do
      its("Other System Events") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205780r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - Other System Events failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Other System Events") { should eq "Failure" }
    end
    describe audit_policy do
      its("Other System Events") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205781r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - Security State Change successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Security State Change records events related to changes in the security state, such as startup and shutdown of the system.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Security State Change") { should eq "Success" }
    end
    describe audit_policy do
      its("Security State Change") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205782r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - Security System Extension successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Security System Extension records events related to extension code being loaded by the security subsystem.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("Security System Extension") { should eq "Success" }
    end
    describe audit_policy do
      its("Security System Extension") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205783r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - System Integrity successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    System Integrity records events related to violations of integrity to the security subsystem.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("System Integrity") { should eq "Success" }
    end
    describe audit_policy do
      its("System Integrity") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205784r569188_rule" do
  title "Windows Server 2019 must be configured to audit System - System Integrity failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    System Integrity records events related to violations of integrity to the security subsystem.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  describe.one do
    describe audit_policy do
      its("System Integrity") { should eq "Failure" }
    end
    describe audit_policy do
      its("System Integrity") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205791r569188_rule" do
  title "Windows Server 2019 must be configured to audit DS Access - Directory Service Access successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Directory Service Access records events related to users accessing an Active Directory object.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    describe.one do
      describe audit_policy do
        its("Directory Service Access") { should eq "Success" }
      end
      describe audit_policy do
        its("Directory Service Access") { should eq "Success and Failure" }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205792r569188_rule" do
  title "Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Directory Service Access records events related to users accessing an Active Directory object.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    describe.one do
      describe audit_policy do
        its("Directory Service Access") { should eq "Failure" }
      end
      describe audit_policy do
        its("Directory Service Access") { should eq "Success and Failure" }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205793r569188_rule" do
  title "Windows Server 2019 must be configured to audit DS Access - Directory Service Changes successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Directory Service Changes records events related to changes made to objects in Active Directory Domain Services.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    describe.one do
      describe audit_policy do
        its("Directory Service Changes") { should eq "Success" }
      end
      describe audit_policy do
        its("Directory Service Changes") { should eq "Success and Failure" }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205794r569188_rule" do
  title "Windows Server 2019 must be configured to audit DS Access - Directory Service Changes failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Audit Directory Service Changes records events related to changes made to objects in Active Directory Domain Services.
    
    Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-002234"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-6 (9)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
    describe.one do
      describe audit_policy do
        its("Directory Service Changes") { should eq "Failure" }
      end
      describe audit_policy do
        its("Directory Service Changes") { should eq "Success and Failure" }
      end
    end
end

control "xccdf_mil.disa.stig_rule_SV-205795r569188_rule" do
  title "Windows Server 2019 account lockout duration must be configured to 15 minutes or greater."
  desc  "
    Vulnerability Discussion: The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002238"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AC-7 b"]
  describe.one do
    describe security_policy do
      its("LockoutDuration") { should eq 0 }
    end
    describe security_policy do
      its("LockoutDuration") { should eq 71582788 }
    end
    describe security_policy do
      its("LockoutDuration") { should be >= 15 }
    end
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205796r569188_rule" do
  title "Windows Server 2019 Application event log size must be configured to 32768 KB or greater."
  desc  "
    Vulnerability Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001849"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-4"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205797r569188_rule" do
  title "Windows Server 2019 Security event log size must be configured to 196608 KB or greater."
  desc  "
    Vulnerability Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001849"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-4"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 196608 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205798r569188_rule" do
  title "Windows Server 2019 System event log size must be configured to 32768 KB or greater."
  desc  "
    Vulnerability Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001849"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-4"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205801r569188_rule" do
  title "Windows Server 2019 must prevent users from changing installation options."
  desc  "
    Vulnerability Discussion: Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001812"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-11 (2)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "EnableUserControl" }
    its("EnableUserControl") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205808r569188_rule" do
  title "Windows Server 2019 must not save passwords in the Remote Desktop Client."
  desc  "
    Vulnerability Discussion: Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205809r569188_rule" do
  title "Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection."
  desc  "
    Vulnerability Discussion: This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fPromptForPassword" }
    its("fPromptForPassword") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205810r569188_rule" do
  title "Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials."
  desc  "
    Vulnerability Discussion: Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "DisableRunAs" }
    its("DisableRunAs") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205811r569188_rule" do
  title "Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "FilterAdministratorToken" }
    its("FilterAdministratorToken") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205812r569188_rule" do
  title "Windows Server 2019 User Account Control must automatically deny standard user requests for elevation."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "ConsentPromptBehaviorUser" }
    its("ConsentPromptBehaviorUser") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205813r569188_rule" do
  title "Windows Server 2019 User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
  desc  "
    Vulnerability Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC.
    
    Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002038"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-11"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableLUA" }
    its("EnableLUA") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205814r569188_rule" do
  title "Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems."
  desc  "
    Vulnerability Discussion: Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001967"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-3 (1)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers and standalone systems.') { domain_role == [2] || domain_role == [3] }
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc") do
      it { should have_property "RestrictRemoteClients" }
      its("RestrictRemoteClients") { should cmp == 1 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205815r569188_rule" do
  title "Windows Server 2019 computer account password must not be prevented from being reset."
  desc  "
    Vulnerability Discussion: Computer account passwords are changed automatically on a regular basis. Disabling automatic password changes can make the system more vulnerable to malicious access. Frequent password changes can be a significant safeguard for the system. A new password for the computer account will be generated every 30 days.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-001967"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "IA-3 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "DisablePasswordChange" }
    its("DisablePasswordChange") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205816r569188_rule" do
  title "Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic."
  desc  "
    Vulnerability Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.
    
    Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002890"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  tag cci: "CCI-003123"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205817r569188_rule" do
  title "Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic."
  desc  "
    Vulnerability Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.
    
    Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002890"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  tag cci: "CCI-003123"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "MA-4 (6)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205819r569188_rule" do
  title "Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers."
  desc  "
    Vulnerability Discussion: Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the server's WINS resolution capability.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-002385"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-5"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters") do
    it { should have_property "NoNameReleaseOnDemand" }
    its("NoNameReleaseOnDemand") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205820r569188_rule" do
  title "Windows Server 2019 domain controllers must require LDAP access signing."
  desc  "
    Vulnerability Discussion: Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. The risk of an attacker pulling this off can be decreased by implementing strong physical security measures to protect the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers.') { domain_role == [5] }
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters") do 
      it { should have_property "LDAPServerIntegrity" }
      its("LDAPServerIntegrity") { should cmp == 2 }
    end
end

control "xccdf_mil.disa.stig_rule_SV-205821r569188_rule" do
  title "Windows Server 2019 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "RequireSignOrSeal" }
    its("RequireSignOrSeal") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205822r569188_rule" do
  title "Windows Server 2019 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled."
  desc  "
    Vulnerability Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "SealSecureChannel" }
    its("SealSecureChannel") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205823r569188_rule" do
  title "Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled, outgoing secure channel traffic will be signed.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "SignSecureChannel" }
    its("SignSecureChannel") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205824r569188_rule" do
  title "Windows Server 2019 must be configured to require a strong session key."
  desc  "
    Vulnerability Discussion: A computer connecting to a domain controller will establish a secure channel. The secure channel connection may be subject to compromise, such as hijacking or eavesdropping, if strong session keys are not used to establish the connection. Requiring strong session keys enforces 128-bit encryption between systems.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "RequireStrongKey" }
    its("RequireStrongKey") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205825r569188_rule" do
  title "Windows Server 2019 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "RequireSecuritySignature" }
    its("RequireSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205826r569188_rule" do
  title "Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: The server message block (SMB) protocol provides the basis for many network operations. If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "EnableSecuritySignature" }
    its("EnableSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205827r569188_rule" do
  title "Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "RequireSecuritySignature" }
    its("RequireSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205828r569188_rule" do
  title "Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."
  desc  "
    Vulnerability Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002418"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8"]
  tag cci: "CCI-002421"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-8 (1)"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "EnableSecuritySignature" }
    its("EnableSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205830r569188_rule" do
  title "Windows Server 2019 Explorer Data Execution Prevention must be enabled."
  desc  "
    Vulnerability Discussion: Data Execution Prevention provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002824"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SI-16"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
      it { should have_property "NoDataExecutionPrevention" }
      its("NoDataExecutionPrevention") { should cmp == 0 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
      it { should_not have_property "NoDataExecutionPrevention" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205832r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Credential Validation records events related to validation tests on credentials for a user account logon.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Credential Validation") { should eq "Success" }
    end
    describe audit_policy do
      its("Credential Validation") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205833r569188_rule" do
  title "Windows Server 2019 must be configured to audit Account Logon - Credential Validation failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Credential Validation records events related to validation tests on credentials for a user account logon.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Credential Validation") { should eq "Failure" }
    end
    describe audit_policy do
      its("Credential Validation") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205835r569188_rule" do
  title "Windows Server 2019 must be configured to audit Logon/Logoff - Special Logon successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Special Logon records special logons that have administrative privileges and can be used to elevate processes.
    
    Satisfies: SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Special Logon") { should eq "Success" }
    end
    describe audit_policy do
      its("Special Logon") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205836r569188_rule" do
  title "Windows Server 2019 must be configured to audit Object Access - Other Object Access Events successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Other Object Access Events") { should eq "Success" }
    end
    describe audit_policy do
      its("Other Object Access Events") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205837r569188_rule" do
  title "Windows Server 2019 must be configured to audit Object Access - Other Object Access Events failures."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  describe.one do
    describe audit_policy do
      its("Other Object Access Events") { should eq "Failure" }
    end
    describe audit_policy do
      its("Other Object Access Events") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205838r569188_rule" do
  title "Windows Server 2019 must be configured to audit logoff successes."
  desc  "
    Vulnerability Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    
    Logoff records user logoffs. If this is an interactive logoff, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.
    
    Satisfies: SRG-OS-000472-GPOS-00217, SRG-OS-000480-GPOS-00227
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000172"
  tag nist: ["NIST SP 800-53", "3", "AU-12 c"]
  tag nist: ["NIST SP 800-53A", "1", "AU-12.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "AU-12 c"]
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe audit_policy do
      its("Logoff") { should eq "Success" }
    end
    describe audit_policy do
      its("Logoff") { should eq "Success and Failure" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205842r569188_rule" do
  title "Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
  desc  "
    Vulnerability Discussion: This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-002450"
  tag nist: ["NIST SP 800-53 Revision 4", "4", "SC-13"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy") do
    it { should have_property "Enabled" }
    its("Enabled") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205858r569188_rule" do
  title "Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."
  desc  "
    Vulnerability Discussion: Configuring the system to disable IPv6 source routing protects against spoofing.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205859r569188_rule" do
  title "Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."
  desc  "
    Vulnerability Discussion: Configuring the system to disable IP source routing protects against spoofing.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205860r569188_rule" do
  title "Windows Server 2019 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."
  desc  "
    Vulnerability Discussion: Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via the shortest path first.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "EnableICMPRedirect" }
    its("EnableICMPRedirect") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205861r569188_rule" do
  title "Windows Server 2019 insecure logons to an SMB server must be disabled."
  desc  "
    Vulnerability Discussion: Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation") do
    it { should have_property "AllowInsecureGuestAuth" }
    its("AllowInsecureGuestAuth") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205862r569188_rule" do
  title "Windows Server 2019 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares."
  desc  "
    Vulnerability Discussion: Additional security requirements are applied to UNC paths specified in hardened UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to these paths.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain-joined systems') { domain_role != [0] || domain_role != [2] }
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\SYSVOL" }
    its("\\\\*\\SYSVOL") { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\NETLOGON" }
    its("\\\\*\\NETLOGON") { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205863r569188_rule" do
  title "Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials."
  desc  "
    Vulnerability Discussion: An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials.  Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation") do
    it { should have_property "AllowProtectedCreds" }
    its("AllowProtectedCreds") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205865r569188_rule" do
  title "Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."
  desc  "
    Vulnerability Discussion: Compromised boot drivers can introduce malware prior to protection mechanisms that load after initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application. At a minimum, drivers determined to be bad must not be allowed.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
      it { should_not have_property "DriverLoadPolicy" }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
      its("DriverLoadPolicy") { should cmp 1 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
      its("DriverLoadPolicy") { should cmp 3 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
      its("DriverLoadPolicy") { should cmp 8 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205866r569188_rule" do
  title "Windows Server 2019 group policy objects must be reprocessed even if they have not changed."
  desc  "
    Vulnerability Discussion: Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the \"Process even if the Group Policy objects have not changed\" option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoGPOListChanges" }
    its("NoGPOListChanges") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205867r569188_rule" do
  title "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery)."
  desc  "
    Vulnerability Discussion: A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (on battery).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "DCSettingIndex" }
    its("DCSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205868r569188_rule" do
  title "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (plugged in)."
  desc  "
    Vulnerability Discussion: A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (plugged in).
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "ACSettingIndex" }
    its("ACSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205869r569188_rule" do
  title "Windows Server 2019 Telemetry must be configured to Security or Basic."
  desc  "
    Vulnerability Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The \"Security\" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. \"Basic\" sends basic diagnostic and usage data and may be required to support some Microsoft services.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") do
      its("AllowTelemetry") { should cmp 0 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") do
      its("AllowTelemetry") { should cmp 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205870r569188_rule" do
  title "Windows Server 2019 Windows Update must not obtain updates from other PCs on the Internet."
  desc  "
    Vulnerability Discussion: Windows Update can obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet. This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates from or sending to systems on the Internet must be prevented.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      its("DODownloadMode") { should cmp 0 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      its("DODownloadMode") { should cmp 1 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      its("DODownloadMode") { should cmp 2 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      its("DODownloadMode") { should cmp 99 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      its("DODownloadMode") { should cmp 100 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205871r569188_rule" do
  title "Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled."
  desc  "
    Vulnerability Discussion: Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
      it { should_not have_property "NoHeapTerminationOnCorruption" }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
      its("NoHeapTerminationOnCorruption") { should cmp == 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205872r569188_rule" do
  title "Windows Server 2019 File Explorer shell protocol must run in protected mode."
  desc  "
    Vulnerability Discussion: The shell protocol will limit the set of folders that applications can open when run in protected mode. Restricting files an application can open to a limited set of folders increases the security of Windows.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
      it { should_not have_property "PreXPSP2ShellProtocolBehavior" }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
      it { should have_property "PreXPSP2ShellProtocolBehavior" }
      its("PreXPSP2ShellProtocolBehavior") { should cmp == 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205873r569188_rule" do
  title "Windows Server 2019 must prevent attachments from being downloaded from RSS feeds."
  desc  "
    Vulnerability Discussion: Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    it { should have_property "DisableEnclosureDownload" }
    its("DisableEnclosureDownload") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205874r569188_rule" do
  title "Windows Server 2019 users must be notified if a web-based program attempts to install software."
  desc  "
    Vulnerability Discussion: Web-based programs may attempt to install malicious software on a system. Ensuring users are notified if a web-based program attempts to install software allows them to refuse the installation.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
      it { should_not have_property "SafeForScripting" }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
      it { should have_property "SafeForScripting" }
      its("SafeForScripting") { should cmp == 0 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205876r569188_rule" do
  title "Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords."
  desc  "
    Vulnerability Discussion: Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to domain controllers') { domain_role == [5] }
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "RefusePasswordChange" }
    its("RefusePasswordChange") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205906r569188_rule" do
  title "Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers."
  desc  "
    Vulnerability Discussion: The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  domain_role = wmi({:namespace=>"root\\cimv2", :query=>"SELECT DomainRole FROM win32_computersystem"}).domainrole
  only_if('This recommendation applies only to member servers') { domain_role == [3] }
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "CachedLogonsCount" }
    its("CachedLogonsCount") { should cmp <= 4 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205909r569188_rule" do
  title "Windows Server 2019 built-in administrator account must be renamed."
  desc  "
    Vulnerability Discussion: The built-in administrator account is a well-known account subject to attack. Renaming this account to an unidentified name improves the protection of this account and the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe powershell("Get-WmiObject -Class win32_useraccount -filter \"name='Administrator'\"") do
    its("stdout") { should eq "" }
    its("exit_status") { should cmp 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205910r569188_rule" do
  title "Windows Server 2019 built-in guest account must be renamed."
  desc  "
    Vulnerability Discussion: The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password. This can allow access to system resources by unauthorized users. Renaming this account to an unidentified name improves the protection of this account and the system.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe powershell("Get-WmiObject -Class win32_useraccount -filter \"name='Guest'\"") do
    its("stdout") { should eq "" }
    its("exit_status") { should cmp 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205911r569188_rule" do
  title "Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less."
  desc  "
    Vulnerability Discussion: Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This must be set to no more than 30 days, ensuring the machine changes its password monthly.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "MaximumPasswordAge" }
    its("MaximumPasswordAge") { should cmp <= 30 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "MaximumPasswordAge" }
    its("MaximumPasswordAge") { should cmp > 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205912r569188_rule" do
  title "Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation."
  desc  "
    Vulnerability Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
      it { should have_property "scremoveoption" }
      its("scremoveoption") { should cmp == 1 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
      it { should have_property "scremoveoption" }
      its("scremoveoption") { should cmp == 2 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-205915r569188_rule" do
  title "Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group."
  desc  "
    Vulnerability Discussion: Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "EveryoneIncludesAnonymous" }
    its("EveryoneIncludesAnonymous") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205916r569188_rule" do
  title "Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."
  desc  "
    Vulnerability Discussion: Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "UseMachineId" }
    its("UseMachineId") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205917r569188_rule" do
  title "Windows Server 2019 must prevent NTLM from falling back to a Null session."
  desc  "
    Vulnerability Discussion: NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "allownullsessionfallback" }
    its("allownullsessionfallback") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205918r569188_rule" do
  title "Windows Server 2019 must prevent PKU2U authentication using online identities."
  desc  "
    Vulnerability Discussion: PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u") do
    it { should have_property "AllowOnlineID" }
    its("AllowOnlineID") { should cmp == 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205920r569188_rule" do
  title "Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing."
  desc  "
    Vulnerability Discussion: This setting controls the signing requirements for LDAP clients. This must be set to \"Negotiate signing\" or \"Require signing\", depending on the environment and type of LDAP server in use.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP") do
    it { should have_property "LDAPClientIntegrity" }
    its("LDAPClientIntegrity") { should cmp >= 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205921r569188_rule" do
  title "Windows Server 2019 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."
  desc  "
    Vulnerability Discussion: Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinClientSec" }
  end
  required_bitmask = 524288
  describe (required_bitmask & registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0").NTLMMinClientSec.to_i) do
    it { should eq 524288 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinClientSec" }
  end
  required_bitmask = 536870912
  describe (required_bitmask & registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0").NTLMMinClientSec.to_i) do
    it { should eq 536870912 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205922r569188_rule" do
  title "Windows Server 2019 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."
  desc  "
    Vulnerability Discussion: Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinServerSec" }
  end
  required_bitmask = 524288
  describe (required_bitmask & registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0").NTLMMinServerSec.to_i) do
    it { should eq 524288 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinServerSec" }
  end
  required_bitmask = 536870912
  describe (required_bitmask & registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0").NTLMMinServerSec.to_i) do
    it { should eq 536870912 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205923r569188_rule" do
  title "Windows Server 2019 default permissions of global system objects must be strengthened."
  desc  "
    Vulnerability Discussion: Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default Discretionary Access Control List (DACL) that specifies who can access the objects with what permissions. When this policy is enabled, the default DACL is stronger, allowing non-administrative users to read shared objects but not to modify shared objects they did not create.
    
    Documentable: false
    
  "
  impact 0.1
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "ProtectionMode" }
    its("ProtectionMode") { should cmp == 1 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-205925r569188_rule" do
  title "Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart."
  desc  "
    Vulnerability Discussion: Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.
    
    Documentable: false
    
  "
  impact 0.5
  tag cci: "CCI-000366"
  tag nist: ["NIST SP 800-53", "3", "CM-6 b"]
  tag nist: ["NIST SP 800-53A", "1", "CM-6.1 (iv)"]
  tag nist: ["NIST SP 800-53 Revision 4", "4", "CM-6 b"]
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "DisableAutomaticRestartSignOn" }
    its("DisableAutomaticRestartSignOn") { should cmp == 1 }
  end
end