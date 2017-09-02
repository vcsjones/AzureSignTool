Azure Sign Tool
===============

Azure Sign Tool is similar to `signtool` in the Windows SDK, with the major difference being that it uses
Azure Key Vault for performing the signing process. The usage is like `signtool`, except with a limited set
of options for signing and options for authenticating to Azure Key Vault.

Example usage:

    AzureKeyVault.exe sign -du "https://vcsjones.com" \
	  -fd sha384 -kvu https://my-vault.vault.azure.net \
	  -kvi 01234567-abcd-ef012-0000-0123456789ab \
	  -kvs <token> \
	  -kvc my-key-name
	  C:\path\to\program.exe
	  
	  
The `--help` or `sign --help` option provides more detail about each parameter.
	  
## Requirements

Windows 10 or Windows Server 2016 is required.

## Current Limitations

Current Timestamping is not available. It can be worked around using the native Windows `signtool`'s `timestamp`
command to timestamp existing signatures.

SHA1 signing is not supported by Azure Key Vault.

Dual signing is not supported. This appears to be a limitation of the API used.