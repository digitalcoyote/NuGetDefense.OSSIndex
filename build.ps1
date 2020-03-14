$content = Get-Content './Src/NuGetDefense.OSSIndex/NuGetDefense.OSSIndex.nuspec'
$Regex = [Regex]::new('(?<=<version>)(\d{0,4}\.\d{0,4}\.\d{0,4}\.{0,1}\d{0,4})(?=<\/version>)')           
$Match = $Regex.Match($content)           
$oldVersion = $Match.Value

$VersionPieces = $oldVersion.Split('.')
$Version = "$($VersionPieces[0]).$($VersionPieces[1]).$($VersionPieces[2]).$([int]$VersionPieces[3] + 1)"
$updatedNuspec = $content.Replace("<version>$oldVersion</version>", "<version>$Version</version>")
Set-Content './Src/NuGetDefense.OSSIndex/NuGetDefense.OSSIndex.nuspec' $updatedNuspec

dotnet build -c Release ./Src/NuGetDefense.OSSIndex/NuGetDefense.OSSIndex.csproj
dotnet pack -c Release ./Src/NuGetDefense.OSSIndex/NuGetDefense.OSSIndex.csproj