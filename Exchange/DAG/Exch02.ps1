<#                       
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |w|w|w|.|r|l|e|v|c|h|e|n|k|o|.|c|o|m|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                                                    

::Exchange 2016 Installation (DSC) + DAG, Second Node
::Required modules: xExchange (1.8.0.0), xPendingReboot and xComputerManagement
::Originally created for VMM Service Templates, unattended installation
::Details: https://rlevchenko.com/2016/10/31/automate-exchange-2016-installation-and-dag-configuration-with-powershell-dsc/     
                                                                                             
 #>

#Variables
param ()
$domainname = "dom-" + $args[0] + '.com' #or get-domain if domain is existed.
$nodename = "srv" + $args[0] + '-' + "EXCH02" #specify name for server
$netbios = "dom-" + $args[0] #NETBIOS name
$gw = "x.x.$($args[0]).1" #define yours or retrieve them by using args
$ip = "x.x.$($args[0]).21"
$dns1 = "x.x.$($args[0]).10"
$dns2 = "x.x.$($args[0]).11"

#Creds for Exchange install acoount
$pwd = ConvertTo-SecureString "Pass1234" -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
      
#Import the certificate for securing MOF (optional. related strings can be just commented out)
$CertPW = ConvertTo-SecureString “Pass123” -AsPlainText -Force
Import-PfxCertificate -Password $certpw -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\ExchInstall\cert\publickey.pfx

#DSC starts here
Configuration InstallExchange

{
    Import-DscResource -Module xExchange #Configures Exchange
    Import-DscResource -Module xPendingReboot #Checks required reboots before/after installations
    Import-DscResource -Module xComputerManagement #Domain joining
    Import-DSCResource -Module xNetworking #DNS+NIC settings

    Node $AllNodes.Where{ $_.Role -eq 'SecondDAGMember' }.NodeName
    {
        $dagSettings = $ConfigData[$Node.DAGId]
        #Sets certificate for LCM on every node
        LocalConfigurationManager {
            CertificateId      = $AllNodes.Thumbprint #set certificate on LCM
            RebootNodeIfNeeded = $true #applies automatic reboots
            ConfigurationMode  = 'ApplyOnly' #disable monitoring features. only apply
        }
        xDhcpClient DisabledDhcpClient #Disable DHCP 
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

        }
        xDnsServerAddress DNSServers #Sets DC01 as a primary DNS Server
        {
           
            Address        = $Node.DNSServerAddresses
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPV4"
            DependsOn      = "[xIPAddress]NewIPAddress"

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
        #Installs UCMA. Don't forget to change path it if it is required
        Package UCMA {
            Ensure    = 'Present'
            Name      = 'Microsoft Unified Communications Managed API 4.0, Core 
                    Runtime 64-bit'
            Path      = 'c:\ExchInstall\UCMA\UcmaRuntimeSetup\ironmansetup.exe' 
            ProductID = 'ED98ABF5-B6BF-47ED-92AB-1CDCAB964447'
            Arguments = '/q'
            
        }
        xComputer DomainJoin #domain joining
        {
            Name       = $nodename
            DomainName = $domainname
            Credential = $creds
            DependsOn  = "[xDnsServerAddress]DNSServers"

        }
        xPendingReboot BeforeReqInstallation #are reboots required?
        {
            Name      = "BeforeReqInstallation"

            DependsOn = '[xComputer]DomainJoin'
        }


        #Checks Exchange Setup Directory (can be changed it's necessary). No recurse.
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
        #Wait while AD Preparation run from EXCH01 finishes
        xExchWaitForADPrep WaitForADPrep
        {
            Identity            = "Doesn'tMatter"
            Credential          = $Creds
            SchemaVersion       = 15326 #OK for EXCH 2016 with CU5
            OrganizationVersion = 16212 #change to 	16213 if you are installing EXCH 2016 with CU5
            DomainVersion       = 13236 #OK for EXCH 2016 with CU5
            DependsOn           = '[xPendingReboot]BeforeExchangeInstall'
        }


        #Does the Exchange install. Verify directory with exchange binaries
        xExchInstall InstallExchange
        {
            Path       = "C:\ExchInstall\Exch\Setup.exe"
            Arguments  = "/mode:Install /role:Mailbox /OrganizationName:""$netbios"" /Iacceptexchangeserverlicenseterms"
            Credential = $Creds

            DependsOn  = '[xExchWaitForADPrep]WaitForADPrep'

        }

        #Sees if a reboot is required after installing Exchange
        xPendingReboot AfterExchangeInstall
        {
            Name      = "AfterExchangeInstall"

            DependsOn = '[xExchInstall]InstallExchange'
        }
        #DAG Configuration | Second node
        xExchWaitForDAG WaitForDAG #waits while DAG becomes online
        {
            Identity   = $dagSettings.DAGName
            Credential = $Creds
        }
        xExchDatabaseAvailabilityGroupMember DAGMember #adds node to DAG
        {
            MailboxServer     = $Node.NodeName
            Credential        = $Creds
            DAGName           = $dagSettings.DAGName
            SkipDagValidation = $true

            DependsOn         = '[xExchWaitForDAG]WaitForDAG'
        }
   
        Script GetStatus { #Creates txt file at the end
            GetScript  = { return $null }
            SetScript  = {
                New-Item -ItemType File -Path C:\DSC\setupisfinished.txt

            }
            TestScript = { Test-Path -Path C:\DSC\setupisfinished.txt }
            DependsOn  = '[xExchDatabaseAvailabilityGroupMember]DAGMember'
            Credential = $creds
        }

 

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
            DAGId                       = 'DAG1'          

        }

        @{
            NodeName           = $nodename
            Role               = "SecondDAGMember"
            DNSServerAddresses = @(
                $dns1
                $dns2
            )
        }
    );
    DAG1     = @( 
        @{
            DAGName = 'dag01'  #DAG Name
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

