Azure Sign Tool
===============

Azure Sign Tool is similar to `signtool` in the Windows SDK, with the major difference being that it uses
Azure Key Vault for performing the signing process. The usage is like `signtool`, except with a limited set
of options for signing and options for authenticating to Azure Key Vault.

Example usage:

    AzureSignTool.exe sign -du "https://vcsjones.com" \
	  -fd sha384 -kvu https://my-vault.vault.azure.net \
	  -kvi 01234567-abcd-ef012-0000-0123456789ab \
	  -kvs <token> \
	  -kvc my-key-name \
	  -tr http://timestamp.digicert.com \
	  -td sha384
	  C:\path\to\program.exe
	  
	  
The `--help` or `sign --help` option provides more detail about each parameter.

## Parameters

* `--azure-key-vault-url` [short: `-kvu`, required: yes]: A fully qualified link to the URL of the key vault with
	the certificate that will be used for signing. An example value might be `https://my-vault.vault.azure.net`.

* `--azure-key-vault-client-id` [short: `-kvi`, required: possibly]: This is the client ID used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option. If this parameter is supplied, `--azure-key-vault-client-secret`
	must be supplied as well.

* `--azure-key-vault-client-secret` [short: `-kvs`, required: possibly]: This is the client secret used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option. If this parameter is supplied, `--azure-key-vault-client-id`
	must be supplied as well.

* `--azure-key-vault-certificate` [short: `-kvc`, required: yes]: The name of the certificate used to perform the signing
	operation.

* `--azure-key-vault-accesstoken` [short: `-kvs`, required: possibly]: An access token used to authenticate to Azure. This
	can be used instead of the `--azure-key-vault-client-id` and `--azure-key-vault-client-secret` options. This is useful
	if AzureSignTool is being used as part of another program that is already authenticated and has an access token to
	Azure.

* `--description` [short: `-d`, required: no]: A description of the signed content. This parameter serves the same purpose
	as the `/d` option in the Windows SDK `signtool`. If this parameter is not supplied, the signature will not contain a
	description.

* `--description-url` [short: `-du`, required: no]: A URL with more information of the signed content. This parameter serves
	the same purpose as the `/du` option in the Windows SDK `signtool`. If this parameter is not supplied, the signature will
	not contain a URL description.

* `--timestamp-rfc3161` [short: `-tr`, required: no]: A URL to an RFC3161 compliant timestamping service. This parameter serves the
	same purpose as the `/tr` option in the Windows SDK `signtool`. This parameter should be used in favor of the `--timestamp` option.
	Using this parameter will allow using modern, RFC3161 timestamps which also support timestamp digest algorithms other than SHA1.

* `--timestamp-authenticode` [short: `-t`, required: no]: A URL to a legacy "Authenticode" timestamping service. This parameter serves the
	same purpose as the `/t` option in the Windows SDK `signtool`. Using a "Authenicode" timestamping service is deprecated.
	Instead, use the `--timestamp-rfc3161` option.

* `--timestamp-digest` [short: `-td`, required: no]: The name of the digest algorithm used for timestamping. This parameter is ignored
	unless the `--timestamp-rfc3161` parameter is also supplied. The default value is `sha256`. Possible values:
	* sha1
	* sha256
	* sha384
	* sha512

* `--file-digest` [short: `-fd`, required: no]: The name of the digest algorithm used for hashing the file being signed.  The default
 	value is `sha256`. Possible values:
	* sha256
	* sha384
	* sha512

## Supported Formats

This tool uses the same mechanisms for signing as the Windows SDK `signtool`. It will support the same formats as `signtool` supports.
However, the formats that `azuresigntool` and `signtool` support vary by operating system and which Subject Interface Pacakges are
present on the system.
	  
## Requirements

Windows 10 or Windows Server 2016 is required.

## Current Limitations

SHA1 signing is not supported by Azure Key Vault.

Dual signing is not supported. This appears to be a limitation of the API used.
