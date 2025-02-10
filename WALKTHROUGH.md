# Walkthroughs

The following basic preparations are required for all guides:

* Obtain a certificate.
* Within your Azure subscription, create an Azure KeyVault. Note the URL of the KeyVault; this will be your input to `-kvu` later.
* Upload your certificate into the KeyVault, giving it a name.

## Using AzureSignTool to sign files with Azure DevOps

*Note*: Sean Killeen has an expanded version of this on his blog, [How to: Use AzureSignTool to sign files with Azure DevOps using a certificate in Azure Key Vault
][1].

* Do you have service connection with service principal authentication(or ready to create one)?
  * Yes - Much simpler [option A](#a--using-existing-service-connection-with-service-principal-authentication) is for you
  * No - Use [option B](#b--using-custom-application-principal)

### A) Using existing service connection with service principal authentication

* Go to KeyVault's the `Access Policies` section.
* Create an access policy that applies to your connection service principal.
* For the access policy, set the below permissions:

  | Area | Permissions |
  | ---- | ----------- |
  | Key | Sign |
  | Secret | Get |
  | Certificate | Get |

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
- task: AzureCLI@2
  displayName: 'Sign outputted .exe with global AzureSignTool'
  inputs:
    scriptType: ps
    scriptLocation: inlineScript
    azureSubscription: '[YOUR_CONNECTION_NAME]'
    addSpnToEnvironment: true
    inlineScript: |
      AzureSignTool sign -du "[YOUR_URL]" -kvu "https://[VAULT_ID].vault.azure.net -kvi $Env:servicePrincipalId -kvt $Env:tenantId -kvs $Env:servicePrincipalKey -kvc "[REDACTED_CERT_NAME]" -v [FILES_YOU_WANT_TO_SIGN]
```

### B) Using custom Application Principal

* Within your Azure AD, register an application with a name (no need to worry about the redirect URL).
* In the overview screen for the application, note the Application ID -- this will be the client ID input into the `-kvi` parameter later.
* Also note the Directory ID -- this will be the tenant ID input into the `-kvt` parameter later.
* Create a client secret for the application and give it a description (e.g. "Access to KeyVault certificate for signing"). Be sure to copy the secret somewhere temporarily, as you won't be able to see it after initially creating it. This secret will be passed into the `-kvs` parameter later.
* Return to your KeyVault's settings, and go to the `Access Policies` section.
* Create an access policy that applies to your registered application, e.g. if the app you registered in AD was called `MyApp`, this policy should apply to the `MyApp` user.
* For the access policy, set the below permissions:

  | Area | Permissions |
  | ---- | ----------- |
  | Key | Sign |
  | Secret | Get |
  | Certificate | Get |

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
    script: AzureSignTool sign -du "[YOUR_URL]" -kvu "https://[VAULT_ID].vault.azure.net" -kvi "[REDACTED_APPLICATION_ID]" -kvt "[REDACTED_DIRECTORY_ID]" -kvs "[REDACTED_APPLICATION_CLIENT_SECRET]" -kvc "[REDACTED_CERT_NAME]" -v [FILES_YOU_WANT_TO_SIGN]
```

## Using AzureSignTool to sign files with GitLab CI

### A) Using service principal authentication

* Go to KeyVault's the `Access Policies` section.
* Create an access policy that applies to your service principal.
* For the access policy, set the below permissions:

  | Area | Permissions |
  | ---- | ----------- |
  | Key | Sign |
  | Secret | Get |
  | Certificate | Get |

* In your GitLab build configuration, add a job to install and execute the AzureSignTool:

```yml
sign:
  stage: deploy
  image: mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2019 # If docker on windows is used.
  before_script:
    - Invoke-WebRequest https://github.com/vcsjones/AzureSignTool/releases/latest/download/AzureSignTool-x64.exe -OutFile AzureSignTool.exe
  script:
    - >
        .\AzureSignTool.exe sign 
        --azure-key-vault-url https://example.vault.azure.net/
        --azure-key-vault-client-id $AZURE_CLIENT_ID
        --azure-key-vault-client-secret $AZURE_CLIENT_SECRET
        --azure-key-vault-tenant-id $AZURE_TENANT_ID
        --azure-key-vault-certificate example-certificate
        --verbose 
        example.exe
  artifacts:
    paths:
      - example.exe
```

### B) Using JWT Tokens authentication (OIDC)

* Configure a [federated identity for GitLab](https://docs.gitlab.com/ee/ci/cloud_services/azure/#create-azure-ad-federated-identity-credentials) in your service principal.
* Go to KeyVault's the `Access Policies` section.
* Create an access policy that applies to your service principal.
* For the access policy, set the below permissions:

  | Area | Permissions |
  | ---- | ----------- |
  | Key | Sign |
  | Secret | Get |
  | Certificate | Get |


* In your GitLab build configuration, add a step to install and execute the AzureSignTool:

```yml
sign:
  stage: deploy
  image: mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2019 # If docker on windows is used.
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: 'https://gitlab.com'
  before_script:
    - az login --service-principal -u $AZURE_CLIENT_ID --tenant $AZURE_TENANT_ID --federated-token $GITLAB_OIDC_TOKEN
    - Invoke-WebRequest https://github.com/vcsjones/AzureSignTool/releases/latest/download/AzureSignTool-x64.exe -OutFile AzureSignTool.exe
  script:
    - >
      .\\AzureSignTool.exe sign 
      --azure-key-vault-url https://example.vault.azure.net/
      --azure-key-vault-managed-identity
      --azure-key-vault-certificate example-certificate
      --verbose 
      example.exe
  artifacts:
    paths:
      - example.exe
```

Happy signing!

[1]: https://seankilleen.com/2020/05/how-to-use-azuresigntool-to-sign-files-with-azure-devops-using-a-certificate-in-azure-keyvault/
