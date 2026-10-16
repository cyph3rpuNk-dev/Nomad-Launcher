# Read-only verifier. Importing this file performs no native test or host mutation.
. (Join-Path $PSScriptRoot 'VmRecovery.Common.ps1')
function Test-VmRecoveryPhaseEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InputDirectory,[Parameter(Mandatory=$true)][string]$OutputDirectory)
    $build=Test-VmBuild $InputDirectory;$receipt=Read-VmJson (Join-Path $OutputDirectory 'RECEIPT.json') 65536
    Assert-VmShape $receipt @('schema','phase','campaign','base_commit','source_tree_sha256','build_manifest_sha256','harness_sha256','bundle_index_sha256','enrollment','os_version','nonloopback_interfaces','default_routes','exit_code','failure','files')
    Assert-VmInteger $receipt.schema 1;Assert-VmInteger $receipt.exit_code 0;Assert-VmInteger $receipt.nonloopback_interfaces 0;Assert-VmInteger $receipt.default_routes 0
    if($null -ne $receipt.failure -or $receipt.phase -cnotin @('Origin','PeerUser','ForeignMachine','ReturnOrigin') -or (Split-Path -Leaf ([IO.Path]::GetFullPath($OutputDirectory))) -cne $receipt.phase){throw 'Native phase did not complete or output scope mismatched.'}
    foreach($key in @('campaign','base_commit','source_tree_sha256')){if($receipt.$key -cne $build.$key){throw 'Build/phase provenance mismatch.'}}
    if($receipt.build_manifest_sha256 -cne (Get-VmHash (Join-Path $InputDirectory 'BUILD-MANIFEST.json')) -or $receipt.harness_sha256 -cne (Get-VmHash (Join-Path $InputDirectory 'NativeVmRecoveryTests.exe')) -or $receipt.bundle_index_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $receipt.os_version -cnotmatch '^10\.\d+\.\d+(?:\.\d+)?$'){throw 'Input/bundle/OS evidence mismatch.'}
    $user=switch($receipt.phase){'Origin'{'NomadRecoverySource'};'PeerUser'{'NomadRecoveryPeer'};'ForeignMachine'{'NomadRecoveryForeign'};'ReturnOrigin'{'NomadRecoverySource'}}
    Assert-VmEnrollment $receipt.enrollment $receipt.phase $user 'inert-local-label' 'inert-local-label' ('C:\Users\'+$user)
    if($receipt.enrollment.campaign -cne $build.campaign){throw 'Enrollment campaign mismatch.'}
    $names=@('RESULT.json','native-stdout.txt','native-stderr.txt');if($receipt.phase -ceq 'Origin'){$names+=@('Transfer/BUNDLE-INDEX.json','Transfer/journal.bin','Transfer/machine.bin','Transfer/nested.bin','Transfer/origin.json','Transfer/user.bin')}
    if(@($receipt.files).Count -ne $names.Count){throw 'Incomplete phase evidence inventory.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($file in $receipt.files){Assert-VmShape $file @('name','bytes','sha256');if($file.name -cnotin $names -or -not $seen.Add($file.name) -or ($file.bytes -isnot [int] -and $file.bytes -isnot [long]) -or $file.bytes -lt 0 -or $file.bytes -gt 65536 -or $file.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Unsafe, duplicated or oversized phase evidence.'};$path=Join-Path $OutputDirectory $file.name;Assert-VmPlainPath $path;$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or $item.Length -ne $file.bytes -or (Get-VmHash $path) -cne $file.sha256){throw 'Phase evidence hash/length mismatch.'}}
    $stdout=Get-Content -LiteralPath (Join-Path $OutputDirectory 'native-stdout.txt') -Raw
    if($stdout -notmatch 'test result: ok\. 1 passed; 0 failed;' -or (Get-Item -LiteralPath (Join-Path $OutputDirectory 'native-stderr.txt')).Length -ne 0){throw 'Exact native completion/stderr not clean.'}
    $result=Read-VmJson (Join-Path $OutputDirectory 'RESULT.json');Assert-VmInteger $result.schema 1;Assert-VmBool $result.qualified $true
    if($result.campaign -cne $build.campaign -or $result.phase -cne $receipt.phase -or $result.scope -cne 'public payload and inert journal only; no host trace scanner invoked'){throw 'Native result scope mismatch.'}
    Assert-VmShape $result.context @('machine','user');foreach($key in @('machine','user')){if($result.context.$key -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid campaign-scoped context fingerprint.'}}
    if($receipt.phase -ceq 'Origin'){
        Assert-VmShape $result @('schema','campaign','phase','context','scope','roundtrip','intent_retained','qualified');Assert-VmBool $result.roundtrip $true;Assert-VmBool $result.intent_retained $true
        $bundle=Test-VmOriginBundle (Join-Path $OutputDirectory 'Transfer') $receipt.bundle_index_sha256 $build.campaign $receipt.harness_sha256
        foreach($key in @('machine','user')){if($bundle.context.$key -cne $result.context.$key){throw 'Origin context/bundle mismatch.'}}
    }else{
        $shape=@('schema','campaign','phase','context','scope','origin_context','same_machine','same_user','nested_payload_refused','user_payload_refused','machine_payload_refused','nested_payload_opened','user_payload_opened','machine_payload_opened','journal_ciphertext_refused','retired','retained','qualified')
        if($receipt.phase -cne 'ReturnOrigin'){$shape+=@('intent_bytes_unchanged')};Assert-VmShape $result $shape;Assert-VmShape $result.origin_context @('machine','user')
        foreach($key in @('machine','user')){if($result.origin_context.$key -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid source context fingerprint.'}}
        $sameMachine=$result.context.machine -ceq $result.origin_context.machine;$sameUser=$result.context.user -ceq $result.origin_context.user
        Assert-VmBool $result.same_machine $sameMachine;Assert-VmBool $result.same_user $sameUser
        $returning=$receipt.phase -ceq 'ReturnOrigin';$peer=$receipt.phase -ceq 'PeerUser'
        Assert-VmBool $result.same_machine ($returning -or $peer);Assert-VmBool $result.same_user $returning
        foreach($key in @('nested_payload_opened','user_payload_opened')){Assert-VmBool $result.$key $returning}
        foreach($key in @('nested_payload_refused','user_payload_refused','journal_ciphertext_refused')){Assert-VmBool $result.$key (-not $returning)}
        Assert-VmBool $result.machine_payload_opened ($returning -or $peer);Assert-VmBool $result.machine_payload_refused (-not ($returning -or $peer))
        if($returning){Assert-VmInteger $result.retired 1;Assert-VmInteger $result.retained 0}else{Assert-VmBool $result.intent_bytes_unchanged $true;Assert-VmInteger $result.retired 0;Assert-VmInteger $result.retained 1}
    }
    [pscustomobject]@{phase=$receipt.phase;campaign=$build.campaign;harness_sha256=$receipt.harness_sha256;bundle_index_sha256=$receipt.bundle_index_sha256;context=$result.context;origin_context=if($receipt.phase -ceq 'Origin'){$result.context}else{$result.origin_context};files_verified=@($receipt.files).Count;receipt_sha256=(Get-VmHash (Join-Path $OutputDirectory 'RECEIPT.json'));qualified=$true;scope='Selected fixture bytes/guest assertions verified; VM independence also requires operator provenance; not browser/forensic or hostile-host attestation'}
}
function Test-VmRecoveryMatrix {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InputDirectory,[Parameter(Mandatory=$true)][string]$OriginDirectory,[Parameter(Mandatory=$true)][string]$PeerUserDirectory,[Parameter(Mandatory=$true)][string]$ForeignMachineDirectory,[Parameter(Mandatory=$true)][string]$ReturnOriginDirectory)
    $rows=@();foreach($pair in @(@('Origin',$OriginDirectory),@('PeerUser',$PeerUserDirectory),@('ForeignMachine',$ForeignMachineDirectory),@('ReturnOrigin',$ReturnOriginDirectory))){$row=Test-VmRecoveryPhaseEvidence $InputDirectory $pair[1];if($row.phase -cne $pair[0]){throw 'Matrix phase mismatch.'};$rows+=@($row)}
    $origin=$rows[0];foreach($row in $rows){if($row.campaign -cne $origin.campaign -or $row.harness_sha256 -cne $origin.harness_sha256 -or $row.bundle_index_sha256 -cne $origin.bundle_index_sha256){throw 'Matrix source/bundle mismatch.'};foreach($key in @('machine','user')){if($row.origin_context.$key -cne $origin.context.$key){throw 'Matrix origin context mismatch.'}}}
    [pscustomobject]@{schema=1;campaign=$origin.campaign;scoped_binding_matrix_verified=$true;phases=$rows;scope='Four public-payload/inert-journal phases with matching source bytes; independently initialized disposable VMs are an operator requirement, not proven by identifiers alone'}
}
