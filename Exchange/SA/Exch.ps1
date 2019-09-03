<#
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |w|w|w|.|r|l|e|v|c|h|e|n|k|o|.|c|o|m|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                                                    
 
::Exchange 2016 Installation (DSC)
::Required modules: xExchange and xPendingReboot
 
 #>
 
#Variables
param ()
#Domain and Netbios Names
$domainname = $args[0] #or get-domain if domain is existed.
$netbios = $DomainName.split(“.”)[0]
 
#Creds for Exchange install acoount
$pwd = ConvertTo-SecureString "Pass123" -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
 
#Import the certificate for securing MOF (optional. related strings can be just commented out)
$CertPW = ConvertTo-SecureString “Pass123” -AsPlainText -Force
Import-PfxCertificate -Password $certpw -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\ExchInstall\cert\publickey.pfx
 
#DSC starts here
Configuration InstallExchange
 
{
    Import-DscResource -Module xExchange
    Import-DscResource -Module xPendingReboot
 
    Node $AllNodes.NodeName
    {
        #Sets certificate for LCM on every node
        LocalConfigurationManager {
            CertificateId      = $AllNodes.Thumbprint
            RebootNodeIfNeeded = $true
            ConfigurationMode  = 'ApplyOnly'
        }
 
        #Installs Required Components for Exchange (note: there is 1 planned automatic reboot)
        WindowsFeature ASHTTP {
            Ensure = 'Present'
            Name   = 'AS-HTTP-Activation'
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
            Path      = 'c:\UCMA\UcmaRuntimeSetup\ironmansetup.exe'
            ProductID = 'ED98ABF5-B6BF-47ED-92AB-1CDCAB964447'
            Arguments = '/q'
 
        }
 
        #Checks Exchange Setup Directory (can be changed it's necessary). No recurse.
        File ExchangeBinaries {
            Ensure          = 'Present'
            Type            = 'Directory'
            Recurse         = $false
            SourcePath      = 'C:\Exch'
            DestinationPath = 'C:\Exch'
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
            Path       = "C:\Exch\Setup.exe"
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
        }
 
        @{
            NodeName = "localhost"
        }
    );
}
 
if ($Creds -eq $null) {
    #if creds are empty -> write to log Application/mozno udalit')
    New-EventLog –LogName Application –Source “Exchange Installation”
    Write-EventLog –LogName Application –Source “Exchange Installation” –EntryType Error –EventID 1 –Message “Credentials are empty”
 
}
 
#Compiles the example
InstallExchange -ConfigurationData $ConfigData -Creds $Creds
 
#Sets up LCM on target computers to decrypt credentials, and to allow reboot during resource execution
Set-DscLocalConfigurationManager -Path .\InstallExchange -Verbose
 
#Pushes configuration and waits for execution
Start-DscConfiguration -Path .\InstallExchange -Verbose -Wait