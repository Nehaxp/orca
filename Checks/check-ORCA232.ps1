<#

232 Checks to determine if ATP Safe attachments response if malware scanning for attachments times out or error occurs is enabled

#>

using module "..\ORCA.psm1"

class ORCA232 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA232()
    {
        $this.Control=232
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe attachments response if malware scanning for attachments times out or error"
        $this.PassText="Safe attachments response if malware scanning for attachments times out or error is enabled"
        $this.FailRecommendation="Enable Safe attachments response if malware scanning for attachments times out or error"
        $this.Importance="ATP Safe attachments response if malware scanning for attachments times out or error occurs helps to determine policy in case malware scanning for attachments time outs or errors"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Attachments Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Safe attachments"="https://protection.office.com/safeattachment"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Enabled = $False

        ForEach($Policy in $Config["SafeAttachmentsPolicy"]) 
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="ActionOnError"
            $ConfigObject.ConfigData=$Policy.ActionOnError

            # Determine if ATP Safe attachments ActionOnError is enabled or not
           
            If($Policy.ActionOnError -eq $False)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            Else 
            {
                $Enabled = $True
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

            }
           
            $this.AddConfig($ConfigObject)
        }

    }

}