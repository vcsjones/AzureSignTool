Azure Sign Tool
===============

The below README is based on functionality in `main` which may not be the same as the latest released version of AzureSignTool. For README information about released versions, please see the README for the version's associated tag. The README for the current release can [be found here](https://github.com/vcsjones/AzureSignTool/blob/v6.0.0/README.md).

Azure Sign Tool is similar to `signtool` in the Windows SDK, with the major difference being that it uses
Azure Key Vault for performing the signing process. The usage is like `signtool`, except with a limited set
of options for signing and options for authenticating to Azure Key Vault.

Example usage:

    AzureSignTool.exe sign -du "https://vcsjones.com" \
	  -fd sha384 -kvu https://my-vault.vault.azure.net \
	  -kvi 01234567-abcd-ef012-0000-0123456789ab \
	  -kvt 01234567-abcd-ef012-0000-0123456789ab \
	  -kvs <token> \
	  -kvc my-key-name \
	  -tr http://timestamp.digicert.com \
	  -td sha384 \
	  -v \
	  -ifl C:\list\of\file\to\sign.txt \
	  C:\additional\file\to\sign\program1.exe \
	  C:\additional\file\to\sign\program2.exe


The `--help` or `sign --help` option provides more detail about each parameter.

[A walk-through is available](WALKTHROUGH.md) if you're interested on getting set up from scratch.

## Installation

AzureSignTool can be installed in a couple of ways.

### NuGet Tool

You can install AzureSignTool from NuGet using

```powershell
dotnet tool install --global --version 6.0.0 AzureSignTool
AzureSignTool.exe
```

It is recommended to specify an exact version such as 6.0.0, or a latest major-minor, like 6.0.* so that major versions, which often include a breaking change, are not automatically picked up.

### Single-file Download

AzureSignTool provides self-contained executables on the GitHub release. For example, to download the v6.0.0 ARM64 installer:

```powershell
Invoke-WebRequest https://github.com/vcsjones/AzureSignTool/releases/download/v6.0.0/AzureSignTool-arm64.exe -OutFile AzureSignTool.exe
.\AzureSignTool.exe
```

See [latest release](https://github.com/vcsjones/AzureSignTool/releases/latest) for available downloads.

### WinGet

AzureSignTool can be install with the WinGet package manager.

```PowerShell
winget install vcsjones.azuresigntool
```

The WinGet package manager installs the same binary this is available from the Single-file Download on the GitHub release. It does not require .NET to be installed.

### Which to use?

The NuGet tool offers smaller downloads that will install faster, however requires the .NET 8 SDK to be present on the system. The NuGet tool supports x64, x86, and ARM64.

The single-file downloads do not require .NET to be installed on the system at all, only to be run on a supported version of Windows. They are entirely stand-alone binaries. This makes them useful in places that .NET is not installed at all, such as a CI pipeline that is not .NET-centric or desired. Single-file currently supports x64 and ARM64. If x86 support is needed, the NuGet tool is required.

## Parameters

* `--azure-key-vault-url` [short: `-kvu`, required: yes]: A fully qualified URL of the key vault with
	the certificate that will be used for signing. An example value might be `https://my-vault.vault.azure.net`.

* `--azure-key-vault-client-id` [short: `-kvi`, required: possibly]: This is the client ID used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option. If this parameter is supplied, `--azure-key-vault-client-secret` and `--azure-key-vault-tenant-id`
	must be supplied as well.

* `--azure-key-vault-client-secret` [short: `-kvs`, required: possibly]: This is the client secret used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option or when using managed identities with `--azure-key-vault-managed-identity`. If this parameter is supplied, `--azure-key-vault-client-id` and `--azure-key-vault-tenant-id` must be supplied as well.

* `--azure-key-vault-tenant-id` [short: `-kvt`, required: possibly]: This is the tenant id used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option or when using managed identities with `--azure-key-vault-managed-identity`. If this parameter is supplied, `--azure-key-vault-client-id` and `--azure-key-vault-client-secret` must be supplied as well.

* `--azure-key-vault-certificate` [short: `-kvc`, required: yes]: The name of the certificate used to perform the signing
	operation.

* `--azure-key-vault-accesstoken` [short: `-kva`, required: possibly]: An access token used to authenticate to Azure. This
	can be used instead of the `--azure-key-vault-managed-identity`, `--azure-key-vault-client-id` and `--azure-key-vault-client-secret` options. This is useful
	if AzureSignTool is being used as part of another program that is already authenticated and has an access token to
	Azure.

* `--azure-key-vault-managed-identity` [short: `-kvm`, required: possibly]: Use the ambiant Managed Identity to authenticate to Azure. This
	can be used instead of the `--azure-key-vault-accesstoken`, `--azure-key-vault-client-id` and `--azure-key-vault-client-secret` options. This option uses a combination of authentication mechanisms listed under [DefaultAzureCredential Class](https://learn.microsoft.com/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet#definition). Beside Managed Identity, this also allows you to use existing sessions in the Azure CLI or PowerShell. It also supports Visual Studio Credentials, Interactive Browser Authentication and others.

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
	* sha1
	* sha256
	* sha384
	* sha512

* `--additional-certificates` [short: `-ac`, required: no]: A list of paths to additional certificates to aide in building a full chain
	for the signing certificate. Azure SignTool will build a chain, either as deep as it can or to a trusted root. This will also use
	the Windows certificate store, in addition to any certificates specified with this option. Specifying this option does not guarantee
	the inclusion of the certificate, only if it is part of the chain. To include multiple certificates, specify this option mulitple
	times, such as `-ac file1.cer -ac file2.cer`. The files specified must be public certificates only. They cannot be PFX, PKCS12 or
	PFX files.

* `--verbose` [short: `-v`, required: no]: Include additional output in the log. This parameter does not accept a value and cannot be
	combine with the `--quiet` option.

* `--quiet` [short: `-q`, required: no]: Do not print output to the log. This parameter does not accept a value and cannot be
	combine with the `--verbose` option. The exit code of the process can be used to determine success or failure of the sign operation.
	
* `--continue-on-error` [short: `-coe`, required: no]: If multiple files to sign are specified, this flag will cause the signing process to
	move on to the next file when signing fails. This flag modifies the exit code of the program. See the Exit Codes section for more
	information.

* `--input-file-list` [short: `-ifl`, required: no]: Specifies a path to a text file which contains a list of files to sign, with one
	file per-line in the text file. If this parameter is specified, it is combined with files directly specified on the command line. The
	distinct result of the two options is signed.

* `--skip-signed` [short: `-s`, required: no]: If a file is already signed it will be skipped, rather than replacing the existing
	signature.

* `--append-signature` [short: `-as`, required: no]: When specified the signing process adds a signature to an existing signature instead of
        replacing it. Requires Windows 11 or later.

### Advanced

* `--page-hashing` [short: `-ph`, required: no]: Causes the Authenticode signing process to generate hashes of pages for verifying when
	the application is paged in to memory. If this flag is omitted, the default configuration for the operating system will be used.
	This flag will not affect non-PE file formats.

* `---no-page-hashing` [short: `-nph`, required: no]: Causes the Authenticode signing process to exclude hashes of pages for verifying when
	the application is paged in to memory. If this flag is omitted, the default configuration for the operating system will be used.
	This flag will not affect non-PE file formats.

* `--max-degree-of-parallelism` [short: `-mdop`, required: no]: When signing multiple files, specifies the maximum number of concurrent
	operations. Setting this value does not guarentee that number of concurrent operations will be performed. If this value is unspecified,
	the system will use the default based on the number of available processor threads. Setting this value to "1" disable concurrent
	signing.

In most circumances, using the defaults for page hashing is recommended, which can be done by simply omitting both of the parameters.

## Supported Formats

This tool uses the same mechanisms for signing as the Windows SDK `signtool`. It will support the same formats as `signtool` supports.
However, the formats that `azuresigntool` and `signtool` support vary by operating system and which Subject Interface Packages are
present on the system.

## Exit Codes

The exit code is an HRESULT. Successfully signing produces a result of `S_OK` ("0"). If all files fail to sign, the exit code is
0xA0000002. If some were signed successfully, the exit code is 0x20000001.

## Cancellation

The standard Ctrl+C key sequence is used to cancel the signing. Any in-flight signing operations are finished, then the process exits with
a status code according to the complete signing operations.

## Requirements

Windows 10 or Windows Server 2016 is required. Some features require later versions of Windows.
