<#                       
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |w|w|w|.|r|l|e|v|c|h|e|n|k|o|.|c|o|m|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                                                    

::Exchange 2016 Installation (DSC) + DAG, First Node
::Required modules: xExchange (1.8.0.0), xPendingReboot and xComputerManagement
::Originally created for VMM Service Templates, unattended installation
::Details: https://rlevchenko.com/2016/x/31/automate-exchange-2016-installation-and-dag-configuration-with-powershell-dsc/                                                                                             
 
#>


#Variables
param ()
#Domain and Netbios Names  
$domainname = "dom-" + $args[0] + '.com' #or get-domain if domain is existed.
$witnessfqdn = "srv" + $args[0] + '-' + "DC02" + '.' + $domainname #fqdn for witness server
$nodename = "srv" + $args[0] + '-' + "EXCH01" #specify name for server
$netbios = "dom-" + $args[0]
$gw = "x.x.$($args[0]).1" #define yours or retrieve them by using args
$ip = "x.x.$($args[0]).20" #ip for this EXCH node
$dns1 = "x.x.$($args[0]).x" # 1 dns server IP 
$dns2 = "x.x.$($args[0]).11" # 2 dns server IP
$dagip = "x.x.$($args[0]).23" # vIP for DAG
     
      
#Main Creds
$pass = "Pass1234" #this "plain" pwd is used by other PScreds 
$pwd = ConvertTo-SecureString $pass -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
      
#Imports the certificate for securing MOF (optional. related strings can be just commented out)
$CertPW = ConvertTo-SecureString “Pass123” -AsPlainText -Force
Import-PfxCertificate -Password $certpw -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\ExchInstall\cert\publickey.pfx

#DSC starts here
Configuration InstallExchange

{
    Import-DscResource -Module xExchange #Node should have these modules installed. It's just import operation
    Import-DscResource -Module xPendingReboot 
    Import-DscResource -Module xComputerManagement
    Import-DSCResource -Module xNetworking 

    Node $AllNodes.Where{ $_.Role -eq 'FirstDAGMember' }.NodeName
    {
        $dagSettings = $ConfigData[$Node.DAGId]
        #Sets certificate for LCM on every node
        LocalConfigurationManager {
            CertificateId      = $AllNodes.Thumbprint #sets certificate for LCM
            RebootNodeIfNeeded = $true #enables automatic reboots
            ConfigurationMode  = 'ApplyOnly' #Default "Apply and Monitor" is not suitable for us
        }
        xDhcpClient DisabledDhcpClient #Disables DHCP 
        {
            State          = 'Disabled'
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPv4"
        }
        xIPAddress NewIPAddress #Sets IPv4 on Ethernet adapter
        {
            IPAddress      = $ip
            InterfaceAlias = "Ethernet"
            SubnetMask     = 24
            AddressFamily  = "IPV4"
            DependsOn      = "[xDhcpClient]DisabledDhcpClient"
        } 
        xDefaultGatewayAddress GW #Sets GW address 
        {
            Address        = $gw
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPv4"
            DependsOn      = "[xIPAddress]NewIPAddress" 
        }
        xDnsServerAddress DNSServers #Sets the primary DNS Server
        {
           
            Address        = $Node.DNSServerAddresses
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPV4"
            DependsOn      = "[xDefaultGatewayAddress]GW"

        }         

        #Installs Required Components for Exchange (note: there is 1 planned automatic reboot)
        WindowsFeature ASHTTP {
            Ensure = 'Present'
            Name   = 'AS-HTTP-Activation'
        }
        WindowsFeature WinBackup {
            Ensure = 'Present'
            Name   = 'Windows-Server-Backup'
        }
        WindowsFeature DesktopExp {
            Ensure = 'Present'
            Name   = 'Desktop-Experience'
        }
        WindowsFeature NetFW45 {
            Ensure = 'Present'
            Name   = 'NET-Framework-45-Features'
        }
        WindowsFeature RPCProxy {
            Ensure = 'Present'
            Name   = 'RPC-over-HTTP-proxy'
        }
        WindowsFeature RSATClus {
            Ensure = 'Present'
            Name   = 'RSAT-Clustering'
        }
        WindowsFeature RSATClusCmd {
            Ensure = 'Present'
            Name   = 'RSAT-Clustering-CmdInterface'
        }
        WindowsFeature RSATClusMgmt {
            Ensure = 'Present'
            Name   = 'RSAT-Clustering-Mgmt'
        }
        WindowsFeature RSATClusPS {
            Ensure = 'Present'
            Name   = 'RSAT-Clustering-PowerShell'
        }
        WindowsFeature WebConsole {
            Ensure = 'Present'
            Name   = 'Web-Mgmt-Console'
        }
        WindowsFeature WAS {
            Ensure = 'Present'
            Name   = 'WAS-Process-Model'
        }
        WindowsFeature WebAsp {
            Ensure = 'Present'
            Name   = 'Web-Asp-Net45'
        }
        WindowsFeature WBA {
            Ensure = 'Present'
            Name   = 'Web-Basic-Auth'
        }
        WindowsFeature WCA {
            Ensure = 'Present'
            Name   = 'Web-Client-Auth'
        }
        WindowsFeature WDA {
            Ensure = 'Present'
            Name   = 'Web-Digest-Auth'
        }
        WindowsFeature WDB {
            Ensure = 'Present'
            Name   = 'Web-Dir-Browsing'
        }
        WindowsFeature WDC {
            Ensure = 'Present'
            Name   = 'Web-Dyn-Compression'
        }
        WindowsFeature WebHttp {
            Ensure = 'Present'
            Name   = 'Web-Http-Errors'
        }
        WindowsFeature WebHttpLog {
            Ensure = 'Present'
            Name   = 'Web-Http-Logging'
        }
        WindowsFeature WebHttpRed {
            Ensure = 'Present'
            Name   = 'Web-Http-Redirect'
        }
        WindowsFeature WebHttpTrac {
            Ensure = 'Present'
            Name   = 'Web-Http-Tracing'
        }
        WindowsFeature WebISAPI {
            Ensure = 'Present'
            Name   = 'Web-ISAPI-Ext'
        }
        WindowsFeature WebISAPIFilt {
            Ensure = 'Present'
            Name   = 'Web-ISAPI-Filter'
        }
        WindowsFeature WebLgcyMgmt {
            Ensure = 'Present'
            Name   = 'Web-Lgcy-Mgmt-Console'
        }
        WindowsFeature WebMetaDB {
            Ensure = 'Present'
            Name   = 'Web-Metabase'
        }
        WindowsFeature WebMgmtSvc {
            Ensure = 'Present'
            Name   = 'Web-Mgmt-Service'
        }
        WindowsFeature WebNet45 {
            Ensure = 'Present'
            Name   = 'Web-Net-Ext45'
        }
        WindowsFeature WebReq {
            Ensure = 'Present'
            Name   = 'Web-Request-Monitor'
        }
        WindowsFeature WebSrv {
            Ensure = 'Present'
            Name   = 'Web-Server'
        }
        WindowsFeature WebStat {
            Ensure = 'Present'
            Name   = 'Web-Stat-Compression'
        }
        WindowsFeature WebStatCont {
            Ensure = 'Present'
            Name   = 'Web-Static-Content'
        }
        WindowsFeature WebWindAuth {
            Ensure = 'Present'
            Name   = 'Web-Windows-Auth'
        }
        WindowsFeature WebWMI {
            Ensure = 'Present'
            Name   = 'Web-WMI'
        }
        WindowsFeature WebIF {
            Ensure = 'Present'
            Name   = 'Windows-Identity-Foundation'
        }
        WindowsFeature RSATADDS {
            Ensure = 'Present'
            Name   = 'RSAT-ADDS'
        }
         
        
        #Domain Joining
        xComputer DomainJoin
        {
            Name       = $nodename
            DomainName = $domainname
            Credential = $creds
            DependsOn  = "[xDnsServerAddress]DNSServers"

        }
        xPendingReboot BeforeReqInstallation #If reboots are required?
        {
            Name      = "BeforeReqInstallation"

            DependsOn = '[xComputer]DomainJoin'
        }

        #Installs UCMA. Don't forget to change path it if it is required
        Package UCMA {
            Ensure    = 'Present'
            Name      = 'Microsoft Unified Communications Managed API 4.0, Core 
                    Runtime 64-bit'
            Path      = 'c:\ExchInstall\UCMA\UcmaRuntimeSetup\ironmansetup.exe'
            ProductID = 'ED98ABF5-B6BF-47ED-92AB-1CDCAB964447'
            Arguments = '/q'
            
        }

        #Checks simply Exchange Setup Directory (can be changed it's necessary). No recurse.
        File ExchangeBinaries {
            Ensure          = 'Present'
            Type            = 'Directory'
            Recurse         = $false
            SourcePath      = 'C:\ExchInstall\Exch'
            DestinationPath = 'C:\ExchInstall\Exch'
        }

        #Checks if a reboot is needed before installing Exchange
        xPendingReboot BeforeExchangeInstall
        {
            Name      = "BeforeExchangeInstall"

            DependsOn = '[File]ExchangeBinaries'
        }

        #Does the Exchange install. Verify directory with exchange binaries
        xExchInstall InstallExchange
        {
            Path       = "C:\ExchInstall\Exch\Setup.exe"
            Arguments  = "/mode:Install /role:Mailbox /OrganizationName:""$netbios"" /Iacceptexchangeserverlicenseterms"
            Credential = $Creds

            DependsOn  = '[xPendingReboot]BeforeExchangeInstall'
        }

        #Sees if a reboot is required after installing Exchange
        xPendingReboot AfterExchangeInstall
        {
            Name      = "AfterExchangeInstall"

            DependsOn = '[xExchInstall]InstallExchange'
        }
        
        Script PrestageCNO { #Prestage is required before DAG configuration. 

            SetScript  = {
                $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator", (ConvertTo-SecureString $using:pass -AsPlainText -Force))
                New-ADComputer -Name DAG01 -DNSHostName DAG01 -DisplayName DAG01 -Enabled $false -Credential $creds -verbose #Creates DAG01 computer account
                $DC = (Get-ADDomainController -Credential $creds).HostName
                ICM -ComputerName $DC -Credential $creds -ScriptBlock {
                    #Variables
                    $dagacc = Get-ADComputer DAG01 #-Credential $creds
                    $dagldap = "LDAP" + '://' + $dagacc.DistinguishedName
                    $dagadsi = New-Object DirectoryServices.DirectoryEntry $dagldap
                    
                    #Sid for DAG and Exch accounts
                    $exchsid = (Get-ADGroup "Exchange Trusted Subsystem").sid
                    $nodesid = (Get-AdComputer -Filter 'Name -like "*EXCH01"').sid
                    
                    #Security principals and rights
                    $exchid = [System.Security.Principal.IdentityReference] $exchsid
                    $nodeid = [System.Security.Principal.IdentityReference] $nodesid
                    $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                    $perm = [System.Security.AccessControl.AccessControlType]::Allow
                   
                    #New Access Rules
                    $exchperm = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $exchid, $rights, $perm
                    $nodeperm = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $nodeid, $rights, $perm
                    
                    #Apply permissions
                    $dagadsi.ObjectSecurity.AddAccessRule($exchperm)
                    $dagadsi.ObjectSecurity.AddAccessRule($nodeperm)
                    $dagadsi.CommitChanges() }
            }
            #If DAG01 computer account is already created - skips SetScript and goes ahead
            TestScript = { $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator", (ConvertTo-SecureString $using:pass -AsPlainText -Force))


                $ErrorActionPreference = 'SilentlyContinue'
                if (-not $( Get-ADComputer -Identity "DAG01" -Credential $creds)) { return $false }
                else { return $true }
                $ErrorActionPreference = 'Continue'  
            }
            GetScript  = {
                return $null
            }
            Credential = $creds
        
            DependsOn  = '[xPendingReboot]AfterExchangeInstall'
        }

        Script WitnessPrep { #Adds Exchange subsystem to administrators group on witness server
            SetScript  = {
                $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator", (ConvertTo-SecureString $using:pass -AsPlainText -Force))
                Invoke-Command -ComputerName $using:witnessfqdn -Credential $creds -ArgumentList $using:netbios -ScriptBlock {
                    New-Item "C:\FSW" -ItemType Directory #actually it's not required (Exchange creates it automatically when witness is in use)
                    net localgroup administrators $args[0]\"Exchange Trusted Subsystem" /add }
                         
            }
            #Simple check of folder existence on Witness. If false - runs SetScript
            TestScript = {
                $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator", (ConvertTo-SecureString $using:pass -AsPlainText -Force))

                ICM -ComputerName $using:witnessfqdn -Credential $creds -ScriptBlock { [System.IO.Directory]::Exists("C:\FSW") }
                     
            }             
                                                            
            GetScript  = {
                return $null
            }
            Credential = $creds

            DependsOn  = '[Script]PrestageCNO'
        
        }

        #DAG Configuration | Root node
        
        xExchDatabaseAvailabilityGroup DAG
        {
            Name                                 = $dagSettings.DAGName
            Credential                           = $creds
            AutoDagTotalNumberOfServers          = $dagSettings.AutoDagTotalNumberOfServers
            AutoDagDatabaseCopiesPerVolume       = $dagSettings.AutoDagDatabaseCopiesPerVolume
            AutoDagDatabasesRootFolderPath       = 'C:\ExchangeDatabases'
            AutoDagVolumesRootFolderPath         = 'C:\ExchangeVolumes'
            DatacenterActivationMode             = "DagOnly"
            DatabaseAvailabilityGroupIPAddresses = $dagSettings.DatabaseAvailabilityGroupIPAddresses 
            ManualDagNetworkConfiguration        = $true
            ReplayLagManagerEnabled              = $true
            SkipDagValidation                    = $true
            WitnessDirectory                     = 'C:\FSW'
            WitnessServer                        = $dagSettings.WitnessServer
        }

        #Add this server as member
        xExchDatabaseAvailabilityGroupMember DAGMember
        {
            MailboxServer     = $AllNodes.NodeName
            Credential        = $Creds
            DAGName           = $dagSettings.DAGName
            SkipDagValidation = $true

            DependsOn         = '[xExchDatabaseAvailabilityGroup]DAG'
        }
        ### 05/x/2016 MailPolicy script is temporarily disabled ###

        <#        Script MailPolicy #New Accepted Domain + Policy
        {
        SetScript =   { $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator",(ConvertTo-SecureString $using:pass -AsPlainText -Force))
                        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$using:nodename/powershell -Authentication Kerberos -Credential $creds -ArgumentList $using:maildom -ScriptBlock {
                        New-AccceptedDomain -Name 'Main Domain' -DomainType Authoritative -DomainName $args[0]
                        New-EmailAddressPolicy -Name 'Main Policy' -EnablePrimarySMTPAddressTemplate "SMTP:%m@$($args[0])" -IncludeRecipients AllRecipients -Priority 1
                        } 
                      }
        TestScript = {  $creds = New-Object Management.Automation.PSCredential("$($using:netbios)\Administrator",(ConvertTo-SecureString $using:pass -AsPlainText -Force))
                        $ErrorActionPreference = 'SilentlyContinue'
                        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$using:nodename/powershell -Authentication Kerberos -Credential $creds -ScriptBlock {
                        if (-not $(Get-AcceptedDomain 'Main Domain' -ErrorAction Ignore)) {return $false} else {return $true} 
                        $ErrorActionPreference = 'Continue'}
                        return $false

                      }    
                                
        GetScript = {return $null}
        Credential = $creds
        DependsOn = '[xExchDatabaseAvailabilityGroupMember]DAGMember'
        } #>

        ### End of change 05/x/2016 ##

        #### Added 28.09.2016 .Creates txt file @end. #####     
   
        Script GetStatus {
            GetScript  = { return $null }
            SetScript  = {
                New-Item -ItemType File -Path C:\DSC\setupisfinished.txt
            }
            TestScript = { Test-Path -Path C:\DSC\setupisfinished.txt }
            DependsOn  = '[xExchDatabaseAvailabilityGroupMember]DAGMember'
            Credential = $creds
        }

        #### End of change (28.09.2016) ##### 

    }
}

#DSC Configuration data 
$ConfigData = @{
    AllNodes = @(
  
        @{
            NodeName                    = "*"
            #Replace thumbprint with yours or use precreated cert	
            CertificateFile             = "C:\ExchInstall\cert\publickey.cer" 
            Thumbprint                  = "cert" 
            PSDscAllowPlainTextPassword = $true
            DAGId                       = 'DAG1' #if you changed it ..u need to replace DAG1 with yours in every strings         
            DNSServerAddresses          = @(
                $dns1
                $dns2
            )
        }

        @{
            NodeName = $nodename
            Role     = "FirstDAGMember"
        }
    );
    DAG1     = @( 
        @{
            DAGName                              = 'dag01'  
            AutoDagTotalNumberOfServers          = 2     
            AutoDagDatabaseCopiesPerVolume       = 2
            DatabaseAvailabilityGroupIPAddresses = $dagip  
            WitnessServer                        = $witnessfqdn
        }
        
    );
}


if ($Creds -eq $null) {
    #if creds are empty -> write to the Application log
    New-EventLog –LogName Application –Source “Exchange Installation”
    Write-EventLog –LogName Application –Source “Exchange Installation” –EntryType Error –EventID 1 –Message “Credentials are empty”

}


#Compiles the example
InstallExchange -ConfigurationData $ConfigData -Creds $Creds

#Sets up LCM on target computers to decrypt credentials, and to allow reboot during resource execution
Set-DscLocalConfigurationManager -Path .\InstallExchange -Verbose

#Pushes configuration and waits for execution
Start-DscConfiguration -Path .\InstallExchange -Verbose -Wait

