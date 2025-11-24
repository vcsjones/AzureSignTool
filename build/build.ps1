# PowerShell < 7 does not handle ZIP files correctly.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7 or higher."
}

$rootDir = $MyInvocation.MyCommand.Path

if (!$rootDir) {
    $rootDir = $psISE.CurrentFile.Fullpath
}

if ($rootDir)  {
    foreach($i in 1..2) {
        $rootDir = Split-Path $rootDir -Parent
    }
}
else {
    throw 'Could not determine root directory of project.'
}

if (![bool](Get-Command -ErrorAction Stop -Type Application dotnet)) {
    throw 'dotnet SDK could not be found.'
}

$winKitDir = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' 'KitsRoot10'

if (!$winKitDir -or !(Test-Path -Path $winKitDir)) {
    throw 'Windows SDK path is not found.'
}

$sdkVersion = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' | Sort-Object Name -Descending | Select-Object -ExpandProperty PSChildName -First 1
$sdkPath = Join-Path -Path $winKitDir -ChildPath 'bin'
$sdkPath = Join-Path -Path $sdkPath -ChildPath $sdkVersion

$architecture = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
$archDirName = switch ($architecture) {
    'ARM64' { 'arm64' }
    'x86' { 'x86' }
    'AMD64' { 'x64' }
    Default { throw 'Unknown architecture' }
}

$sdkBinPath = Join-Path -Path $sdkPath -ChildPath $archDirName
$objDir = Join-Path -Path $rootDir -ChildPath 'obj'
$outDir = Join-Path -Path $rootDir -ChildPath 'out'

pushd $rootDir

Remove-Item -Path $objDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $objDir -ItemType Directory

Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $outDir -ItemType Directory

dotnet pack -p:OutputFileNamesWithoutVersion=true -p:ContinuousIntegrationBuild=true -c Release -o $objDir src\AzureSign.Core\AzureSign.Core.csproj
dotnet pack -p:OutputFileNamesWithoutVersion=true -p:ContinuousIntegrationBuild=true -c Release -o $objDir src\AzureSignTool\AzureSignTool.csproj

Expand-Archive -Path $objDir\AzureSign.Core.nupkg -DestinationPath $objDir\AzureSign.Core.nupkg.dir
Expand-Archive -Path $objDir\AzureSignTool.nupkg -DestinationPath $objDir\AzureSignTool.nupkg.dir

Remove-Item -Path $objDir\AzureSign.Core.nupkg
Remove-Item -Path $objDir\AzureSignTool.nupkg

& "$sdkBinPath\signtool.exe" sign /d "AzureSign.Core" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSign.Core.nupkg.dir\lib\net8.0\AzureSign.Core.dll"
& "$sdkBinPath\signtool.exe" sign /d "AzureSign.Core" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSign.Core.nupkg.dir\lib\netstandard2.0\AzureSign.Core.dll"
& "$sdkBinPath\signtool.exe" sign /d "AzureSignTool"  /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSignTool.nupkg.dir\tools\net8.0\any\AzureSignTool.dll"
& "$sdkBinPath\signtool.exe" sign /d "AzureSignTool"  /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSignTool.nupkg.dir\tools\net10.0\any\AzureSignTool.dll"

Copy-Item -Path "$objDir\AzureSign.Core.nupkg.dir\lib\net8.0\AzureSign.Core.dll" -Destination "$objDir\AzureSignTool.nupkg.dir\tools\net8.0\any\AzureSign.Core.dll"
Copy-Item -Path "$objDir\AzureSign.Core.nupkg.dir\lib\net8.0\AzureSign.Core.dll" -Destination "$objDir\AzureSignTool.nupkg.dir\tools\net10.0\any\AzureSign.Core.dll"

Compress-Archive -Path "$objDir\AzureSign.Core.nupkg.dir\*" -DestinationPath "$objDir\AzureSign.Core.nupkg"
Compress-Archive -Path "$objDir\AzureSignTool.nupkg.dir\*" -DestinationPath "$objDir\AzureSignTool.nupkg"

dotnet nuget sign --certificate-fingerprint 68821304869e065c24e0684eb43bf974e124642f3437f2ff494a93bb371d029a --hash-algorithm SHA384 --timestamper "http://timestamp.digicert.com" --overwrite "$objDir\AzureSign.Core.nupkg"
dotnet nuget sign --certificate-fingerprint 68821304869e065c24e0684eb43bf974e124642f3437f2ff494a93bb371d029a --hash-algorithm SHA384 --timestamper "http://timestamp.digicert.com" --overwrite "$objDir\AzureSignTool.nupkg"

Copy-Item -Path "$objDir\AzureSign.Core.nupkg" -Destination "$outDir\AzureSign.Core.nupkg"
Copy-Item -Path "$objDir\AzureSignTool.nupkg" -Destination "$outDir\AzureSignTool.nupkg"

dotnet publish -f net10.0 -c Release -r win-arm64 -p:ContinuousIntegrationBuild=true -o "$objDir\AzureSignTool-arm64" .\src\AzureSignTool\AzureSignTool.csproj
dotnet publish -f net10.0 -c Release -r win-x64 -p:ContinuousIntegrationBuild=true -o "$objDir\AzureSignTool-x64" .\src\AzureSignTool\AzureSignTool.csproj

& "$sdkBinPath\signtool.exe" sign /d "AzureSignTool" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSignTool-x64\AzureSignTool.exe"
& "$sdkBinPath\signtool.exe" sign /d "AzureSignTool" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AzureSignTool" "$objDir\AzureSignTool-arm64\AzureSignTool.exe"

Copy-Item -Path "$objDir\AzureSignTool-x64\AzureSignTool.exe" -Destination "$outDir\AzureSignTool-x64.exe"
Copy-Item -Path "$objDir\AzureSignTool-arm64\AzureSignTool.exe" -Destination "$outDir\AzureSignTool-arm64.exe"

popd