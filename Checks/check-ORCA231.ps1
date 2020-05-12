<#

ORCA-231 Checks to determine if Safe attachments redict is enabled
#>

using module "..\ORCA.psm1"

class ORCA231 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA231()
    {
        $this.Control=231
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe attachments Redirect attachment on Detection"
        $this.PassText="Safe attachments Redirect attachment on Detection is Enabled and Redirect Address is set"
        $this.FailRecommendation="Set Safe attachments Redirect attachment on detection should be Enabled and Redirect Address should be set to security administrator email address"
        $this.Importance=" When Redirect attachment on Detection is Enabled and Redirect Address is set to email address for a security administrator that knows how to determine if the attachment is malware or not it enables Safe attachment Advanced Threat Protection Policies"
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
            $ConfigObject.ConfigItem="Redirect"
            $ConfigObject.ConfigData=$Policy.Redirect

            # Determine if ATP Safe attachments redirect is enabled or not
           
            If($Policy.Redirect -eq $False)
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