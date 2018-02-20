########################################
# NSX App Deploy for DISA
# February 20, 2018
# Written by George Lamb using sample code from Nick Bradford and Anthony Burke
#     fixed several bugs from original code

########################################
# To use - edit and update variables with correct values.  Minimal sanity checking is done,
# but be sure you use correct values for your environment.
# Script has modular functions to deploy the 3TierApp into an existing NSX environment.  It
#    assumes NSX is deployed with a provider edge, DLR, and transit network configured.  The
#    app is deployed in stages that can be used for a demo without impacting existing deployed
#    resources.  The steps to use are:
#  1 - Deploy the routing, switching and LB configuration
#      Run> Nsx3TA-funct.ps1 -deploy:$true
#      Web, App, and DB switches will be created, routing will be configured on DLR, (2) LBs
#      will be created on edge, with pools and app groups
#        -- Note does not yet add secondary addresses for VIP
#  2 - Deploy the OVA
#      Run> Nsx3TA-funct.ps1 -deployOva:$true
#      OVA will be deployed to above created switches
#  3 -Deploy microsegmentation 
#       Run> Nsx3TA-funct.ps1 -deployMicroSeg:$true
#        -- Opens up vApp vs. Default Deny, assuming Default Deny is already set for the environment.
#  4 - Clean up everything
#       - Run> Nsx3TA-funct.ps1 -delete:$true
#
# Note:  If you are using NSX 6.2.3 or above, you will need to configure the license key
# in the below variable section.
#   DLR created and dynamic routing configured to edge
#   Script will create 3 logical networks + (2) LB + security groups + OVF deployment
#

<#
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 2, as published by the Free Software Foundation.
This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTIBILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License version 2 for more details.
You should have received a copy of the General Public License version 2 along with this program.
If not, see https://www.gnu.org/licenses/gpl-2.0.html.
The full text of the General Public License 2.0 is provided in the COPYING file.
Some files may be comprised of various open source software components, each of which
has its own license that is located in the source code of the respective component.”
#>

#Requires -version 3.0
#Requires -modules PowerNSX, VMware.VimAutomation.Core

param (
    [switch]$delete=$false,
    [switch]$deploy=$false,
    [switch]$deployOva=$false,
    [switch]$deployMicroSeg=$false
)


#############################################
# NSX Infrastructure Configuration.  Adjust to suit environment.
$NsxManagerName = "nsxl01"
$NsxManagerPassword = "P@ssw0rd"
$NsxManagerIpAddress = "172.29.138.32"
$TransportZoneName = "DISA-GLOBAL"       

# vSphereDetails
$VcenterServer = "vcl01.disa.amer.dsc.local"
$vCenterUserName = "administrator@vsphere.local"
$vCenterPassword = "P@ssw0rd"

$ComputeClusterName = "DISA-Primary-Prod-1"            
$ComputeDatastoreName = "DISA-Primary-Prod-1-LUN01"    
$ComputeVdsName = "DSwitch-Prod-1"             

$EdgeClusterName = $ComputeClusterName
$EdgeDatastoreName = $ComputeDatastoreName

# VDS Network Details
$ComputeNetworkPortGroupName = "DISA-Prod"
$ComputeNetworkSubnetMask = "255.255.255.0"
$ComputeNetworkSubnetPrefixLength = "24"
$ComputeNetworkGateway = "172.29.14.1"
$VxlanMtuSize = 1600

# 3-Tier Application OVA:  Get v1.6 of the vApp from http://goo.gl/ujxYz1
# $3TiervAppLocation = "C:\Downloads\3_Tier-App-v1.6.ova"
$3TiervAppLocation = "C:\Users\george.lamb\Downloads\3_Tier-App-v1.6.ova"
# vApp name to deploy
$vAppName = "DISA-auto"

#############################################
# Edge parameters for configuring LB VIPS
# Edge must pre-exist before deploying 3-tier app
$EdgeName = "DISA-EDGE"
$EdgeUplinkSecondaryAddress   = "172.29.141.7"
$EdgeInternalSecondaryAddress = "192.168.42.4"
$DLRName = "DISA-DLR"
$TransitLsName = "DISA-TRANSIT"

############################################
# Deploy Topology Details.
# Logical Switch Names
$WebPrefix = "AUTO-Web"
$AppPrefix = "AUTO-App"
$DbPrefix = "AUTO-Db"

$WebLsName = "$WebPrefix-10"
$AppLsName = "$AppPrefix-10"
$DbLsName = "$DbPrefix-10"

$DefaultSubnetMask = "255.255.255.0"
$DefaultSubnetBits = "24"

# WebTier VMs
$WebGatewayAddress = "10.0.1.1"
$Web01Name = "$WebPrefix-01"
$Web01Ip = "10.0.1.11"
$Web02Name = "$WebPrefix-02"
$Web02Ip = "10.0.1.12"

# AppTier VMs
$AppGatewayAddress = "10.0.2.1"
$App01Name = "$AppPrefix-01"
$App01Ip = "10.0.2.11"
$App02Name = "$AppPrefix-02"
$App02Ip = "10.0.2.12"

# DB Tier VMs
$DbGatewayAddress = "10.0.3.1"
$Db01Name = "$DbPrefix-01"
$Db01Ip = "10.0.3.11"
 
# LoadBalancer
$WebPoolName = "$WebPrefix-Pool"
$WebPoolDesc = "Created by automation script for Web Tier"
$WebVipName = "$WebPrefix-VIP"
$WebVipIP = $EdgeUplinkSecondaryAddress   
$WebAppProfileName = "$WebPrefix-Profile"

$AppPoolName = "$AppPrefix-Pool"
$AppPoolDesc = "Created by automation script for App Tier"
$AppVipName = "$AppPrefix-VIP"
$AppVipIP = $EdgeInternalSecondaryAddress   
$AppAppProfileName = "$AppPrefix-Profile"

$LbAlgo = "round-robin"
$VipProtocol = "http"
$HttpPort = "80"
$LBMonitorName = "default_http_monitor"

# DFW
$FirewallSectionName = "FW-$vAppName"

#VIP IP Sets--used by Service Composer
$VIPPublicIpSetName = "$vAppName-vips"
$VIPAppIpSetName = "$AppPrefix-vips"

# Security Groups--used by Service Composer
$WebSgName = "SG-$WebPrefix"
$AppSgName = "SG-$AppPrefix"
$DbSgName = "SG-$DbPrefix"
$vAppSgName = "SG-$vAppName"
$DefaultSgDescription = "Group created by automation script"

# Security Tags--used by Service Composer
$WebStName = "ST-$WebPrefix"
$AppStName = "ST-$AppPrefix"
$DbStName = "ST-$DbPrefix"

###############################################
# Do Not modify below here.
###############################################

###############################################
# Constants
$WaitStep = 30
$WaitTimeout = 600
$yesnochoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$yesnochoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$yesnochoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

###############################
# Validation
# 1. Connect to vCenter
# 2. Check for PG, DS, Cluster
function Go-ConnectNSX
{
    write-Host -foregroundcolor DarkGreen "Connecting to vCenter and NSX Manager..."

    try {
        write-Host -foregroundcolor DarkGreen "Connecting to vCenter $VcenterServer ..."
        if ( -not $DefaultViConnection.IsConnected ) {
            connect-ViServer -Server $VcenterServer -User $vCenterUserName -Password $vCenterPassword -WarningAction Ignore | out-null
        }
        write-Host -foregroundcolor DarkGreen "Connecting to NSX $NsxManagerIpAddress ..."
        Connect-NsxServer -NsxServer $NsxManagerIpAddress -Username 'admin' -password $NsxManagerPassword -VIUsername $vCenterUserName -VIPassword $vCenterPassword -ViWarningAction Ignore -DebugLogging | out-null
    }
    catch {
        Throw "Failed connecting.  Check connection details and try again.  $_"
    }
}


# ValidateEnvironment
# 1. validate transport zone exists
# 2. validate edge and DLR exist
# 3. validate transit switch is created
function Go-Validate
{
    write-Host -foregroundcolor DarkGreen "Validating the deployment environment..."
    if ( -not (Get-NsxTransportZone) ) {
        throw "TransportZone does not exist.  $_"
    }
    if ( -not ( get-NsxEdge -Name $EdgeName ) ) {
        throw "Edge $EdgeName must exist to deploy.  Please configure."
    }
    if ( -not ( get-NsxLogicalRouter $DLRName ) ) {
        throw "Logical Router $DLRName must exist to deploy.  Please configure."
    }
    if ( -not ( get-NsxLogicalSwitch $TransitLsName ) ) {
        throw "Transit DLR must exist to deploy.  Please remove and try again."
    }
}


# DeployRouteSwitch
# 1. validate
# 2. Create logical switches
# 3. Create LB
function Go-DeployRouteSwitch
{
    write-Host -foregroundcolor DarkGreen "Preparing to deploy switches and gateways..."

    # Check if things already exist and warn before building
    if ( Get-NsxLogicalSwitch $WebLsName ) {
        throw "Logical Switch $WebLsName already exists.  Please remove and try again."
    }
    if ( Get-NsxLogicalSwitch $AppLsName ) {
        throw "Logical Switch $AppLsName already exists.  Please remove and try again."
    }
    if ( Get-NsxLogicalSwitch $DbLsName ) {
        throw "Logical Switch $DbLsName already exists.  Please remove and try again."
    }
  
    # Create Logical Switches and interfaces
    write-host -foregroundcolor DarkGreen "Getting DLR and Creating Logical Switches..."
    try {
        $TransportZone = Get-NsxTransportZone
        $DLR = Get-NsxLogicalRouter $DLRName
    
        write-host -foregroundcolor DarkGreen "Creating LS $WebLsName"
        $WebLs = $TransportZone | New-NsxLogicalSwitch $WebLsName
        write-host -foregroundcolor DarkGreen "   Adding"  $WebLs.Name "to DLR"
        $DLR | New-NsxLogicalRouterInterface -Type Internal -name $WebLsName  -ConnectedTo $WebLs -PrimaryAddress $WebGatewayAddress -SubnetPrefixLength $DefaultSubnetBits | out-null

        write-host -foregroundcolor DarkGreen "Creating LS $AppLsName"
        $AppLs = $TransportZone | New-NsxLogicalSwitch $AppLsName
        write-host -foregroundcolor DarkGreen "   Adding"  $AppLs.Name "to DLR"
        $DLR | New-NsxLogicalRouterInterface -Type Internal -name $AppLsName  -ConnectedTo $AppLs -PrimaryAddress $AppGatewayAddress -SubnetPrefixLength $DefaultSubnetBits | out-null

        write-host -foregroundcolor DarkGreen "Creating LS $DbLsName"
        $DbLs = $TransportZone | New-NsxLogicalSwitch $DbLsName
        write-host -foregroundcolor DarkGreen "   Adding"  $DbLs.Name "to DLR"
        $DLR | New-NsxLogicalRouterInterface -Type Internal -name $DbLsName  -ConnectedTo $DbLs -PrimaryAddress $DbGatewayAddress -SubnetPrefixLength $DefaultSubnetBits | out-null
   }
   catch {
        Throw "Failed to create logical switches $_"
   }
}

####################################
# Deploy3LoadBalancer
# 1. enable load balancing on edge
# 2. create pools
# 3. create application profiles
# 4. create VIPS--make sure edge secondary address is configured in advance!
function Go-DeployLoadBalancer
{
    # Assume environment is validated.
    write-host -foregroundcolor DarkGreen "Deploying Load Balancer on $EdgeName"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer| Set-NsxLoadBalancer -Enabled | out-null

    # Make sure to re-get the edge & loadBalancer each time it is modified, or it will be out of sync and throw a server error
    $LbMon = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerMonitor -Name $LBMonitorName
    write-host -foregroundcolor DarkGreen "   Using monitor:" $LbMon.monitorId
    
    # Define Web pool members and create pools
    write-host -foregroundcolor DarkGreen "Creating Web Pool: $WebPoolName"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post
    $WebPool = $LoadBalancer | New-NsxLoadBalancerPool -name $WebPoolName -Algorithm $LbAlgo -Description $WebPoolDesc -Monitor $LbMon -Transparent:$false
    $WebPool = $WebPool | Add-NsxLoadBalancerPoolMember -name $Web01Name -IpAddress $Web01Ip -Port $HttpPort
    $WebPool = $WebPool | Add-NsxLoadBalancerPoolMember -name $Web02Name -IpAddress $Web02Ip -Port $HttpPort

    # Define App pool members and create pools
    write-host -foregroundcolor DarkGreen "Creating App Pool: $AppPoolName"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post
    $AppPool = $LoadBalancer | New-NsxLoadBalancerPool -name $AppPoolName -Algorithm $LbAlgo -Description $AppPoolDesc -Monitor $LbMon -Transparent:$false 
    $AppPool = $AppPool | Add-NsxLoadBalancerPoolMember -name $App01Name -IpAddress $App01Ip -Port $HttpPort
    $AppPool = $AppPool | Add-NsxLoadBalancerPoolMember -name $App02Name -IpAddress $App02Ip -Port $HttpPort

    # Create App Profiles.
    write-host -foregroundcolor DarkGreen "Creating Application Profile for Web: $WebAppProfileName"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post
    $WebAppProfile = $LoadBalancer | New-NsxLoadBalancerApplicationProfile -Name $WebAppProfileName  -Type $VipProtocol
    write-host -foregroundcolor DarkGreen "Creating Application Profile for App: $AppAppProfileName"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post
    $AppAppProfile = $LoadBalancer | new-NsxLoadBalancerApplicationProfile -Name $AppAppProfileName  -Type $VipProtocol

    # set secondary addresses on Edge for VIPs
    write-host -foregroundcolor DarkGreen "Future: add option to update secondary addresses for VIPs"
#    $EdgeUplinkInterfaceName = "EDGE-UPLINK"
#    $address = Get-NsxEdge $EdgeName | Get-NsxEdgeInterface -Name $EdgeUplinkInterfaceName | Get-NsxEdgeInterfaceAddress
#    $addStr = -join($address.secondaryAddresses.ipAddress, ",", $EdgeUplinkSecondaryAddress) 
#    $addrSpec = New-NsxAddressSpec -PrimaryAddress $address.primaryAddress -SubnetPrefixLength $address.subnetPrefixLength -SecondaryAddresses $addStr
#    $newaddress = Get-NsxEdge $EdgeName | Get-NsxEdgeInterface -Name $EdgeUplinkInterfaceName | Add-NsxEdgeInterfaceAddress $addrSpec

#    $interface = Get-NsxEdge $EdgeName | Get-NsxEdgeInterface -Name $EdgeUplinkInterfaceName
#    $address = $interface | Get-NsxEdgeInterfaceAddress
#    $addrSpec = New-NsxAddressSpec -PrimaryAddress $address.primaryAddress -SubnetPrefixLength $address.subnetPrefixLength -SecondaryAddresses $address.secondaryAddresses.ipAddress,$testAddress
#    $newaddress = Get-NsxEdge $EdgeName | Get-NsxEdgeInterface -Name $EdgeName | Set-NsxEdgeInterface -name $interface.name -AddressSpec $addrSpec -type $interface.type -ConnectedTo $interface.portgroupName
   
    # Create the VIPs for the relevent WebPools. Using the Secondary interfaces.
    write-host -foregroundcolor DarkGreen "Creating VIPs--make sure VIPs are set as Edge secondary addresses prior"
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post 
    $LoadBalancer | Add-NsxLoadBalancerVip -name $WebVipName -Description $WebVipName -ipaddress $EdgeUplinkSecondaryAddress -Protocol $VipProtocol -Port $HttpPort -ApplicationProfile $WebAppProfile -DefaultPool $WebPool -AccelerationEnabled | out-null
    $LoadBalancer = Get-NSXEdge $EdgeName | Get-NsxLoadBalancer   # need to reget LB and edge after post 
    $LoadBalancer | Add-NsxLoadBalancerVip -name $AppVipName -Description $AppVipName -ipaddress $EdgeInternalSecondaryAddress -Protocol $VipProtocol -Port $HttpPort -ApplicationProfile $AppAppProfile -DefaultPool $AppPool -AccelerationEnabled | out-null
}


####################################
# DeployOva
# 1. Validate everything to deploy OFV
# 2. setup OVA
# 3. deploy
function Go-DeployOva
{
    write-host -foregroundcolor DarkGreen "Deploying 3-Tier App OVF: $3TiervAppLocation"
    #Check that the vCenter env looks correct for OVF deployment.
    try {
        $TransportZone = Get-NsxTransportZone -ErrorAction Stop
        $ComputeCluster = Get-Cluster $ComputeClusterName -errorAction Stop
        $ComputeDatastore = Get-Datastore $ComputeDatastoreName -errorAction Stop
        $EdgeCluster = get-cluster $EdgeClusterName -errorAction Stop
        $EdgeDatastore = get-datastore $EdgeDatastoreName -errorAction Stop
        $CompVds = $ComputeCluster | get-vmhost | Get-VdSwitch $ComputeVdsName -errorAction Stop
        if ( -not $CompVds ) { 
            throw "Compute cluster hosts are not configured with dvs: $ComputeVdsName."
        }
        if ( -not ( test-path $3TiervAppLocation )) { 
            throw "$3TiervAppLocation not found. $_"
        }
        if ( get-vapp $vAppName -ErrorAction SilentlyContinue ) {
            throw "vApp already exists.  Please remove and try again."
        }
        # PowerCLI 6 is required due to OvfConfiguration commands.
        [int] $PowerCliMajorVersion = (get-module -name VMware.VimAutomation.Core).Version.Major
        if ( -not ($PowerCliMajorVersion -ge 6 ) ) { 
            throw "OVF deployment tools requires PowerCLI version 6 or above" 
        }
    }
    catch {
        throw "Failed validating vSphere Environment. $_"
    }

    # Compute details - finds the connected host with the least used memory for deployment.
    $DeploymentVMHost = $Computecluster | Get-VMHost | Sort ConnectionState,MemoryUsageGB | Select -first 1
    if ( -not ( Test-Connection $($DeploymentVMHost.name) -count 1 -ErrorAction Stop )) {
        throw "Unable to validate connection to ESX host $($DeploymentVMHost.Name) used to deploy OVF to."
    }
    write-host -foregroundcolor DarkGreen "Deploy host is: $($DeploymentVMHost.Name)"

    # vCenter and the VDS have no understanding of a "Logical Switch". It only sees it as a VDS portgroup.
    # This step uses Get-NsxBackingPortGroup to determine the actual PG name that the VM attaches to.
    # Also - realise that a single LS could be (and is here) backed by multiple PortGroups, so we need to
    # get the PG in the right VDS (compute)
    # First work out the VDS used in the compute cluster (This assumes you only have a single VDS per cluster.
    # If that isnt the case, we need to get the VDS by name....:
    $WebNetwork = $TransportZone | get-NsxLogicalSwitch $WebLsName | Get-NsxBackingPortGroup | Where { $_.VDSwitch -eq $CompVds }
    $AppNetwork = $TransportZone | get-NsxLogicalSwitch $AppLsName | Get-NsxBackingPortGroup | Where { $_.VDSwitch -eq $CompVds }
    $DbNetwork  = $TransportZone | get-NsxLogicalSwitch $DbLsName | Get-NsxBackingPortGroup | Where { $_.VDSwitch -eq $CompVds }

    # Get OVF configuration so we can modify it.
    $OvfConfiguration = Get-OvfConfiguration -Ovf $3TiervAppLocation

    # Network attachment.
    $OvfConfiguration.NetworkMapping.vxw_dvs_24_virtualwire_3_sid_10001_Web_LS_01.Value = $WebNetwork.name
    $OvfConfiguration.NetworkMapping.vxw_dvs_24_virtualwire_4_sid_10002_App_LS_01.Value = $AppNetwork.name
    $OvfConfiguration.NetworkMapping.vxw_dvs_24_virtualwire_5_sid_10003_DB_LS_01.Value = $DbNetwork.name

    # VM details.
    $OvfConfiguration.common.app_ip.Value = $EdgeInternalSecondaryAddress
    $OvfConfiguration.common.Web01_IP.Value = $Web01Ip
    $OvfConfiguration.common.Web02_IP.Value = $Web02Ip
    $OvfConfiguration.common.Web_Subnet.Value = $DefaultSubnetMask
    $OvfConfiguration.common.Web_Gateway.Value = $WebGatewayAddress
    $OvfConfiguration.common.App01_IP.Value = $App01Ip
    $OvfConfiguration.common.App02_IP.Value = $App02Ip
    $OvfConfiguration.common.App_Subnet.Value = $DefaultSubnetMask
    $OvfConfiguration.common.App_Gateway.Value = $AppGatewayAddress
    $OvfConfiguration.common.DB01_IP.Value = $DB01Ip
    $OvfConfiguration.common.DB_Subnet.Value = $DefaultSubnetMask
    $OvfConfiguration.common.DB_Gateway.Value = $DbGatewayAddressAddress

    # Run the deployment.
    Import-vApp -Source $3TiervAppLocation -OvfConfiguration $OvfConfiguration -Name $vAppName -Location $ComputeCluster -VMHost $DeploymentVmhost -Datastore $ComputeDatastore | out-null
    write-host -foregroundcolor DarkGreen "Starting $vAppName vApp components"
    try {
        Start-vApp $vAppName
    }
    catch {
        write-Host "Issue starting the vApp. Check if it has finished deploying. Press a key to continue";
        $Key = [console]::ReadKey($true)
    }
}


####################################
# Go-DeployMicroseg
# 1. Setup OVA
# 2. call OVA deploy
function Go-DeployMicroseg 
{
    write-Host -foregroundcolor DarkGreen "Deploying microsegmentation for app security..."

    # Check for prior deployment
    try {
        if ( get-NsxSecurityGroup $WebSgName ) {
            throw "Security Group $WebSgName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityGroup $AppSgName ) {
            throw "Security Group $AppSgName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityGroup $DbSgName ) {
            throw "Security Group $DbSgName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityGroup $vAppSgName ) {
            throw "Security Group $vAppSgName exists.  Please remove and try again."
        }
        if ( get-nsxfirewallsection $FirewallSectionName ) {
            throw "Firewall Section $FirewallSectionName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityTag $WebStName ) {
            throw "Security Tag $WebStName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityTag $AppStName ) {
            throw "Security Tag $AppStName exists.  Please remove and try again."
        }
        if ( get-NsxSecurityTag $DbStName ) {
            throw "Security Tag $DbStName exists.  Please remove and try again."
        }
        if ( Get-nsxipset $VIP_IpSet_Name ) {
            throw "IPSet  $VIP_IpSet_Name exists.  Please remove and try again."
        }
    }
    catch {
        write-host -foregroundcolor "DarkGreen" "Prior config variables exist. $_"
    }

    #Create Security Tags
    $WebSt = New-NsxSecurityTag -name $WebStName
    $AppSt = New-NsxSecurityTag -name $AppStName
    $DbSt = New-NsxSecurityTag -name $DbStName

    # Create IP Sets
    write-host -foregroundcolor "DarkGreen" "Creating Source IP Groups"
    $PublicIPSet = New-NsxIPSet -name $VIPPublicIpSetName -IPAddresses $EdgeUplinkSecondaryAddress 
    $AppVIPIpSet = New-NsxIPSet -Name $VIPAppIpSetName -IPAddresses $EdgeInternalSecondaryAddress
    
    #Create SecurityGroups and with static includes
    write-host -foregroundcolor "DarkGreen" "Creating Security Groups"
    $WebSg = New-NsxSecurityGroup -name $WebSgName -description $DefaultSgDescription -includemember $WebSt
    $AppSg = New-NsxSecurityGroup -name $AppSgName -description $DefaultSgDescription -includemember $AppSt
    $DbSg = New-NsxSecurityGroup -name $DbSgName -description $DefaultSgDescription -includemember $DbSt
    $VappSg = New-NsxSecurityGroup -name $vAppSgName -description $vAppSgName -includemember $WebSg, $AppSg, $DbSg

    # Apply Security Tag to VM's for Security Group membership
    $thisVapp = Get-VApp -name $vAppName
    $WebVMs = Get-Vm -Location $thisVapp | ? {$_.name -match ("Web0")}
    $AppVMs = Get-Vm -Location $thisVapp | ? {$_.name -match ("App0")}
    $DbVMs = Get-Vm -Location $thisVapp | ? {$_.name -match ("Db0")}

    $WebSt | New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine $WebVMs | Out-Null
    $AppSt | New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine $AppVMs | Out-Null
    $DbSt | New-NsxSecurityTagAssignment -ApplyToVm -VirtualMachine $DbVMs | Out-Null

    #Building firewall section with value defined in $FirewallSectionName
    write-host -foregroundcolor "DarkGreen" "Creating Firewall Section"
    $FirewallSection = new-NsxFirewallSection $FirewallSectionName
  
    # Assume these services exist which they do in a default NSX deployment.
    $HttpService = Get-NsxService -name "tcp-80" 
    $MySqlService = Get-NsxService -name "tcp-3306" 
    #Actions
    $Allow = "allow"
    $Deny = "deny"

    #Set firewall rules, NOTE: need to reget FW section after each new rule
    #Allows Web VIP to reach WebTier
    write-host -foregroundcolor "DarkGreen" "Creating Web Tier rule"
    $SourcesRule = get-NsxFirewallSection $FirewallSectionName | New-NSXFirewallRule -Name "VIP to Web" -Source $PublicIPSet -Destination $WebSg -Service $HttpService -Action $Allow -AppliedTo $WebSg -position bottom

    #Allows Web tier to reach App Tier via the APP VIP and then the NAT'd vNIC address of the Edge
    write-host -foregroundcolor "DarkGreen" "Creating Web to App Tier rules"
    $WebToAppVIP = get-NsxFirewallSection $FirewallSectionName | New-NsxFirewallRule -Name "$WebSgName to App VIP" -Source $WebSg -Destination $AppVIPIpSet -Service $HttpService -Action $Allow -AppliedTo $WebSg, $AppSg -position bottom
    $ESGToApp = get-NsxFirewallSection $FirewallSectionName | New-NsxFirewallRule -Name "App ESG interface to $AppSgName" -Source $AppVIPIpSet -Destination $AppSg -service $HttpService -Action $Allow -AppliedTo $AppSg -position bottom

    #Allows App tier to reach DB Tier directly
    write-host -foregroundcolor "DarkGreen" "Creating Db Tier rules"
    $AppToDb = get-nsxfirewallsection $FirewallSectionName | New-NsxFirewallRule -Name "$AppSgName to $DbSgName" -Source $AppSg -Destination $DbSg -Service $MySqlService -Action $Allow -AppliedTo $AppSg, $DbSG -position bottom

    write-host -foregroundcolor "DarkGreen" "Overriding default deny for $vAppSgName"
    #Default rule that wraps around all VMs within the topolgoy - application specific DENY ALL
    $vAppAllowAll = get-nsxfirewallsection $FirewallSectionName | New-NsxFirewallRule -Name "Deny All" -Action $Allow -AppliedTo $VappSg -position bottom -EnableLogging -tag "$VappSG"
}



####################################
# Go-Delete
# 1. Delete Interfaces and switches
# 2. Delete LB pools and services
# 3. Delete security groups
# 4. Delete OVA
function Go-Delete
{
    write-host -foregroundcolor DarkGreen "Deleting 3 Tier App"
    write-host -foregroundcolor DarkGreen "Removing DLR interfaces..."
    $DLR = Get-NsxLogicalRouter $DLRName
    if ( $DLR ) {
        write-host -foregroundcolor DarkGreen "Removing $WebLsName from DLR"
        $Interface = $DLR | Get-NsxLogicalRouterInterface -Name $WebLsName
        if ($Interface) {
           Remove-NsxLogicalRouterInterface $Interface -confirm:$false | out-null
        }

        write-host -foregroundcolor DarkGreen "Removing $AppLsName from DLR"
        $Interface = $DLR | Get-NsxLogicalRouterInterface -Name $AppLsName
        if ($Interface) {
            Remove-NsxLogicalRouterInterface $Interface -confirm:$false | out-null
        }

        write-host -foregroundcolor DarkGreen "Removing $DbLsName from DLR"
        $Interface = $DLR | Get-NsxLogicalRouterInterface -Name $DbLsName
        if ($Interface) {
            Remove-NsxLogicalRouterInterface $Interface -confirm:$false | out-null
         }
    }

    # Delete the OVF
    write-host -foregroundcolor DarkGreen "Stopping and removing vApp: $vAppName"
    $MyVapp = Get-VApp -Name $vAppName
    try {
        if ( $MyVapp ) {
            Stop-VApp -VApp $MyVapp -Confirm:$false -Force | out-null
            Remove-VApp -VApp $MyVapp -Confirm:$false
        }
    }
    catch {
        Throw "Failed to delete vApp: $_"
    }

    write-host -foregroundcolor DarkGreen "Removing $WebLsName $AppLsName $DbLsName"
    Get-NsxLogicalSwitch $WebLsName | Remove-NsxLogicalSwitch -confirm:$false
    Get-NsxLogicalSwitch $AppLsName | Remove-NsxLogicalSwitch -confirm:$false
    Get-NsxLogicalSwitch $DbLsName | Remove-NsxLogicalSwitch -confirm:$false

    #delete the LB VIP
    write-host -foregroundcolor DarkGreen "Deleting VIPs $WebVipName, $AppVipName"
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerVip -name $WebVipName | Remove-NsxLoadBalancerVip -confirm:$false
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerVip -name $AppVipName | Remove-NsxLoadBalancerVip -confirm:$false

    #delete LB App profile
    write-host -foregroundcolor DarkGreen "Deleting Application Profiles: $WebAppProfileName, $AppAppProfileName"
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerApplicationProfile -name $WebAppProfileName | Remove-NsxLoadBalancerApplicationProfile -confirm:$false
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerApplicationProfile -name $AppAppProfileName | Remove-NsxLoadBalancerApplicationProfile -confirm:$false

    #delete LB Pools
    write-host -foregroundcolor DarkGreen "Deleting LB Pools: $WebPoolName, $AppPoolName"
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerPool -name $WebPoolName | Remove-NsxLoadBalancerPool -confirm:$false | out-null
    Get-NSXEdge $EdgeName | Get-NsxLoadBalancer | Get-NsxLoadBalancerPool -name $AppPoolName | Remove-NsxLoadBalancerPool -confirm:$false | out-null


    #Delete microsegmentation
    write-host -foregroundcolor "DarkGreen" "Deleting microsegmentation configuration"
    #Delete FW Rules and FW Rule Section
    Get-NsxFirewallSection $FirewallSectionName | Get-NsxFirewallRule -Name "VIP to Web" | Remove-NSXFirewallRule -confirm:$false
    Get-NsxFirewallSection $FirewallSectionName | Get-NsxFirewallRule -Name "$WebSgName to App VIP" | Remove-NSXFirewallRule -confirm:$false
    Get-NsxFirewallSection $FirewallSectionName | Get-NsxFirewallRule -Name "App ESG interface to $AppSgName" | Remove-NSXFirewallRule -confirm:$false
    Get-nsxfirewallsection $FirewallSectionName | Get-NsxFirewallRule -Name "$AppSgName to $DbSgName" | Remove-NSXFirewallRule -confirm:$false
    Get-nsxfirewallsection $FirewallSectionName | Get-NsxFirewallRule -Name "Deny All" | Remove-NSXFirewallRule -confirm:$false
    Get-nsxfirewallsection $FirewallSectionName | Remove-NsxFirewallSection -confirm:$false

    #Delete Security Tag assignments
    Get-NsxSecurityTag -name $WebStName | Get-NsxSecurityTagAssignment | Remove-NsxSecurityTagAssignment -confirm:$false
    Get-NsxSecurityTag -name $AppStName | Get-NsxSecurityTagAssignment | Remove-NsxSecurityTagAssignment -confirm:$false
    Get-NsxSecurityTag -name $DbStName | Get-NsxSecurityTagAssignment | Remove-NsxSecurityTagAssignment -confirm:$false
        
    #Delete SecurityGroups 
    Get-NsxSecurityGroup -name $WebSgName | Remove-NsxSecurityGroup -confirm:$false
    Get-NsxSecurityGroup -name $AppSgName | Remove-NsxSecurityGroup -confirm:$false
    Get-NsxSecurityGroup -name $DbSgName | Remove-NsxSecurityGroup -confirm:$false
    Get-NsxSecurityGroup -name $vAppSgName | Remove-NsxSecurityGroup -confirm:$false
    
    #Delete Security Tags
    Get-NsxSecurityTag -name $WebStName | Remove-NsxSecurityTag -confirm:$false
    Get-NsxSecurityTag -name $AppStName | Remove-NsxSecurityTag -confirm:$false
    Get-NsxSecurityTag -name $DbStName | Remove-NsxSecurityTag  -confirm:$false

    #Delete IP Sets
    Get-NsxIpSet -name $VIPPublicIpSetName | Remove-NsxIpSet -confirm:$false
    Get-NsxIPSet -Name $VIPAppIpSetName | Remove-NsxIpSet -confirm:$false

}


#################################
#  Main Code for script
#

try {
    if ( -not ($deploy -or $deployOva -or $deployMicroSeg -or $delete)) {
        $scriptName = $MyInvocation.MyCommand.Name
        write-host -foregroundcolor DarkGreen "Usage: $scriptName -deploy:`$$true -deployOva:`$$true -deployMicroSeg:`$$true"
        write-host -foregroundcolor DarkGreen "Usage: $scriptName -delete:`$$true"
        exit
    }

    Go-ConnectNSX
    if ( $deploy -or $deployOva ) {
        Go-Validate
    }
    If ( $deploy ) {
        Go-DeployRouteSwitch
        Go-DeployLoadBalancer
    }
    # OVA depends on route and switch being configured
    If ( $deployOva ) {
        Go-DeployOva
    }
    # Microseg depends on the OVA being deployed
    If ( $deployMicroSeg ) {
        Go-DeployMicroseg
    }
    If ( $delete ) {
        Go-Delete
    }
}
catch {
    Throw "Error encountered: $_"
}