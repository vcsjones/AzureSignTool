# Walkthrough: Using AzureSignTool to sign files with Azure DevOps

A lightweight guide on how to use this tool in context.

* Obtain a certificate.
* Within your Azure subscription, create an Azure KeyVault. Note the URL of the KeyVault; this will be your input to `-kvu` later.
* Upload your certificate into the KeyVault, giving it a name.
* Within your Azure AD, register an application with a name (no need to worry about the redirect URL).
* In the overview screen for the application, note the Application ID -- this will be the client ID input into the `-kvi` parameter later.
* Create a client secret for the application and give it a description (e.g. "Access to KeyVault certificate for signing"). Be sure to copy the secret somewhere temporarily, as you won't be able to see it after initially creating it. This secret will be passed into the `-kvs` parameter later.
* Return to your KeyVault's settings, and go to the `Access Policies` section.
* Create an access policy that applies to your registered application, e.g. if the app you registered in AD was called `MyApp`, this policy should apply to the `MyApp` user.
* For the access policy, set the below permissions:

| Area | Permissions |
| ---- | ----------- |
| Key | Verify, Sign, Get, List |
| Secret | Get, List |
| Certificate | Get, List |

* In your Azure DevOps build configuration, add a step to install the global tool:

```yml
- task: DotNetCoreCLI@2
  inputs:
    command: 'custom'
    custom: 'tool'
    arguments: 'install --global azuresigntool'
  displayName: Install AzureSignTool
```

* In your Azure DevOps build configuration, add a step to use the tool, with the values we captured earlier in the bracketed placeholders:

```yml
- task: CmdLine@2
  displayName: 'Sign outputted .exe with global AzureSignTool'
  inputs:
    script: AzureSignTool sign -du "[YOUR_URL]" -kvu "https://[VAULT_ID].vault.azure.net" -kvi "[REDACTED_APPLICATION_ID]" -kvs "[REDACTED_APPLICATION_CLIENT_SECRET" -kvc "[REDACTED_CERT_NAME]" -v [FILES_YOU_WANT_TO_SIGN]
```

At this point, the build should be able to run and sign the files you have listed.

Happy signing!
