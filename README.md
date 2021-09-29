# Azure-Seamless-SSO-Brute-Force

A quick nasty brute forcer for seamless SSO written in powershell, initial POC modified from https://securecloud.blog/2019/12/26/reddit-thread-answer-azure-ad-autologon-endpoint/.

I'm terrible at PowerShell so theres likely to be bugs, feel free to submit pull requests.

Failed authentications do not currently create log files, however successful logins will.

This tool will return a valid password & SAML token (if password found). If MFA is not enabled on the target account it will also print the user details.

Disclaimer: Only use for testing infrastructure you have permission to test!
