# Functions only. Filters public fixture DNS observations; never exports raw NetLog.
Set-StrictMode -Version Latest
function Get-DnsField($Object,[string]$Name) {
    if ($null -eq $Object) {return $null}
    if ($Object -is [Collections.IDictionary]) {if($Object.Contains($Name)){return ,($Object[$Name])};return $null}
    $property=$Object.PSObject.Properties[$Name]
    if ($null -ne $property) {return ,($property.Value)}
    return $null
}
function Test-DnsInteger($Value) {return ($Value -is [int] -or $Value -is [long])}
# Chromium serializes uint32 source IDs through signed int32, including a negative partition.
function Test-DnsSourceId($Value) {return ((Test-DnsInteger $Value) -and $Value -ge [int]::MinValue -and $Value -le [int]::MaxValue)}
function Get-DnsObservation($Log,[string]$Probe,[ValidateSet('Baseline','Failure')][string]$Case,[ValidateSet('Loopback','Quad9Blocked')][string]$FailureTransport='Loopback') {
    if($Case -ceq 'Baseline' -and $FailureTransport -cne 'Loopback'){throw 'Failure transport cannot label a baseline.'}
    if ($Probe -cnotmatch '^nomad-[a-f0-9]{32}-(baseline|failure)\.example\.com$') {throw 'Only the public test probe is accepted.'}
    if (-not $Probe.EndsWith('-'+$Case.ToLowerInvariant()+'.example.com',[StringComparison]::Ordinal)) {throw 'Case/probe mismatch.'}
    $constants=Get-DnsField $Log 'constants'
    $types=Get-DnsField $constants 'logEventTypes';$phases=Get-DnsField $constants 'logEventPhase'
    if ($null -eq $types -or $null -eq $phases) {throw 'Missing NetLog symbol dictionaries.'}
    $names=@{};$phaseNames=@{}
    foreach($property in $types.PSObject.Properties){
        if (-not (Test-DnsInteger $property.Value) -or $property.Value -lt 0 -or $names.ContainsKey([string]$property.Value)) {throw 'Invalid/duplicate event symbol.'}
        $names[[string]$property.Value]=$property.Name
    }
    foreach($name in @('PHASE_BEGIN','PHASE_END','PHASE_NONE')) {
        $value=Get-DnsField $phases $name
        if (-not (Test-DnsInteger $value) -or $phaseNames.ContainsKey([string]$value)) {throw 'Invalid phase symbols.'}
        $phaseNames[[string]$value]=$name
    }
    $events=Get-DnsField $Log 'events'
    if ($null -eq $events -or @($events).Count -gt 200000) {throw 'Missing/oversized event inventory.'}
    $selected=New-Object 'Collections.Generic.List[object]'
    $sourceEvents=@{};$targetIds=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $systemTarget=$false;$knownEndpoints=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $allowed=@('DNS_TRANSACTION','DNS_TRANSACTION_QUERY','DNS_TRANSACTION_HTTPS_ATTEMPT','DNS_TRANSACTION_ATTEMPT','DNS_TRANSACTION_TCP_ATTEMPT','DNS_TRANSACTION_PLATFORM_ATTEMPT','DNS_TRANSACTION_RESPONSE','DOH_URL_REQUEST','URL_REQUEST_START_JOB','HOST_RESOLVER_SYSTEM_TASK')
    $index=0
    foreach($event in $events) {
        $index++
        $type=Get-DnsField $event 'type';$phase=Get-DnsField $event 'phase';$source=Get-DnsField $event 'source';$id=Get-DnsField $source 'id'
        if (-not (Test-DnsInteger $type) -or -not (Test-DnsInteger $phase) -or -not (Test-DnsSourceId $id) -or -not $names.ContainsKey([string]$type) -or -not $phaseNames.ContainsKey([string]$phase)) {throw 'Invalid event identity or phase.'}
        $name=$names[[string]$type];$phaseName=$phaseNames[[string]$phase]
        if ($name -cnotin $allowed) {continue}
        if ($id -eq 0) {throw 'Selected DNS/request event has no source identity.'}
        $params=Get-DnsField $event 'params';$hostname=Get-DnsField $params 'hostname'
        $row=[pscustomobject]@{index=$index;name=$name;phase=$phaseName;source_id=[string]$id;params=$params}
        if (-not $sourceEvents.ContainsKey([string]$id)) {$sourceEvents[[string]$id]=New-Object 'Collections.Generic.List[object]'}
        $sourceEvents[[string]$id].Add($row)
        if ($name -ceq 'DNS_TRANSACTION' -and $phaseName -ceq 'PHASE_BEGIN' -and $hostname -is [string] -and $hostname.TrimEnd('.') -ceq $Probe) {$null=$targetIds.Add([string]$id)}
        if ($name -ceq 'HOST_RESOLVER_SYSTEM_TASK' -and $phaseName -ceq 'PHASE_BEGIN' -and $hostname -is [string] -and $hostname.TrimEnd('.') -ceq $Probe) {$systemTarget=$true}
        if ($name -ceq 'URL_REQUEST_START_JOB' -and $phaseName -ceq 'PHASE_BEGIN') {
            $url=Get-DnsField $params 'url';$uri=$null
            if ($url -is [string] -and [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and -not $uri.UserInfo) {
                if ($uri.Host -cin @('dns.quad9.net','services.helium.imput.net','127.0.0.1')) {$null=$knownEndpoints.Add($uri.Host)}
            }
        }
    }
    $success=$false;$failed=$false;$plain=$systemTarget;$linkedAttempts=0
    $endpoint=if($Case -ceq 'Baseline' -or $FailureTransport -ceq 'Quad9Blocked'){'https://dns.quad9.net/dns-query'}else{'https://127.0.0.1:9/dns-query'}
    foreach($id in $targetIds) {
        $rows=$sourceEvents[$id]
        foreach($row in $rows) {
            if($row.name -cin @('DNS_TRANSACTION_ATTEMPT','DNS_TRANSACTION_TCP_ATTEMPT','DNS_TRANSACTION_PLATFORM_ATTEMPT')){$plain=$true}
            if($row.name -ceq 'DNS_TRANSACTION' -and $row.phase -ceq 'PHASE_BEGIN'){$selected.Add(@{event=$row.name;phase=$row.phase;source_id=$id;hostname=$Probe;index=$row.index})}
        }
        foreach($attempt in @($rows | Where-Object name -CEQ 'DNS_TRANSACTION_HTTPS_ATTEMPT')) {
            $dependency=Get-DnsField $attempt.params 'source_dependency';$dohId=Get-DnsField $dependency 'id'
            if (-not (Test-DnsSourceId $dohId) -or $dohId -eq 0 -or -not $sourceEvents.ContainsKey([string]$dohId)) {continue}
            $dohRows=$sourceEvents[[string]$dohId]
            $jobs=@($dohRows | Where-Object {$_.name -ceq 'URL_REQUEST_START_JOB' -and $_.phase -ceq 'PHASE_BEGIN'})
            if($jobs.Count -eq 0){continue}
            $correct=$true
            foreach($job in $jobs) {
                $url=Get-DnsField $job.params 'url';$uri=$null
                if($url -isnot [string] -or -not [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$uri) -or $uri.UserInfo -or $uri.GetLeftPart([UriPartial]::Path) -cne $endpoint){$correct=$false;break}
            }
            if(-not $correct){continue}
            $linkedAttempts++
            $selected.Add(@{event='DNS_TRANSACTION_HTTPS_ATTEMPT';source_id=$id;dependency_id=[string]$dohId;endpoint=$endpoint;index=$attempt.index})
            foreach($response in @($rows | Where-Object name -CEQ 'DNS_TRANSACTION_RESPONSE')) {
                $dep=Get-DnsField (Get-DnsField $response.params 'source_dependency') 'id';$rcode=Get-DnsField $response.params 'rcode';$answers=Get-DnsField $response.params 'answer_count'
                if((Test-DnsSourceId $dep) -and $dep -ne 0 -and [string]$dep -ceq [string]$dohId -and $response.index -gt $attempt.index -and (Test-DnsInteger $rcode) -and $rcode -cin @(0,3) -and (Test-DnsInteger $answers) -and $answers -ge 0) {
                    $expectedError=if($rcode -eq 0){0}else{-105}
                    foreach($end in @($rows | Where-Object {$_.name -ceq 'DNS_TRANSACTION' -and $_.phase -ceq 'PHASE_END' -and $_.index -gt $response.index})) {
                        $error=Get-DnsField $end.params 'net_error';if($null -eq $error){$error=0}
                        if((Test-DnsInteger $error) -and $error -eq $expectedError){$success=$true;$selected.Add(@{event='DNS_TRANSACTION_RESPONSE';source_id=$id;dependency_id=[string]$dohId;rcode=$rcode;answer_count=$answers;net_error=$error;index=$response.index})}
                    }
                }
            }
            foreach($end in @($rows | Where-Object {$_.name -ceq 'DNS_TRANSACTION' -and $_.phase -ceq 'PHASE_END' -and $_.index -gt $attempt.index})) {
                $error=Get-DnsField $end.params 'net_error'
                if((Test-DnsInteger $error) -and $error -lt 0 -and $error -ne -105){$failed=$true;$selected.Add(@{event='DNS_TRANSACTION';phase='PHASE_END';source_id=$id;net_error=$error;index=$end.index})}
            }
        }
    }
    if($selected.Count -gt 256){throw 'Selected observation budget exceeded.'}
    $status='inconclusive'
    if($plain){$status='classic_or_system_target_attempt_observed'}
    elseif($Case -ceq 'Baseline' -and $success){$status='secure_query_response_observed'}
    elseif($Case -ceq 'Failure' -and $linkedAttempts -gt 0 -and $failed -and -not $success){$status='failed_doh_no_plain_attempt_in_capture'}
    [pscustomobject]@{schema=1;case=$Case;probe=$Probe;status=$status;target_transactions=$targetIds.Count;correlated_doh_attempts=$linkedAttempts;secure_response_observed=$success;failed_doh_transaction_observed=$failed;plain_target_attempt_observed=$plain;known_https_hosts=@($knownEndpoints | Sort-Object);selected_events=@($selected.ToArray());all_packet_leak_absence_proven=$false;scope='Source-correlated browser NetLog observations only; no OS packet capture or complete traffic/installer history'}
}

function Test-DnsEvidenceExport([string]$InputDirectory,[string]$OutputDirectory) {
    $build=Read-RIJson (Join-Path $InputDirectory 'BUILD-MANIFEST.json')
    $receipt=Read-RIJson (Join-Path $OutputDirectory 'GUEST-RECEIPT.json') 16384
    if($build.schema -ne 1 -or $build.target -cne 'x86_64-pc-windows-msvc' -or $receipt.schema -ne 1 -or $receipt.case -cnotin @('Baseline','Failure') -or $receipt.token -cnotmatch '^[a-f0-9]{32}$' -or $receipt.export_token -cnotmatch '^[a-f0-9]{32}$' -or (Split-Path -Leaf $OutputDirectory) -cne ($receipt.case.ToLowerInvariant()+'-'+$receipt.token+'-'+$receipt.export_token)){throw 'Invalid DNS receipt scope.'}
    if($build.base_commit -cnotmatch '^[a-f0-9]{40}$' -or $build.source_tree_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $build.launcher_sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Invalid DNS build provenance.'}
    if((Get-FileHash -LiteralPath (Join-Path $InputDirectory 'Nomad-Helium.exe')).Hash -cne $build.launcher_sha256){throw 'DNS launcher identity mismatch.'}
    foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){if($receipt.$key -cne $build.$key){throw 'DNS build/receipt mismatch.'}}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($inputFile in $build.input_files){
        if($inputFile.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($inputFile.name)){throw 'Unexpected DNS input inventory.'}
        $path=Join-Path $InputDirectory $inputFile.name;Assert-RIPlain $path
        if((Get-Item -LiteralPath $path).Length -ne $inputFile.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $inputFile.sha256){throw 'DNS input hash mismatch.'}
    }
    if($seen.Count -ne 4 -or @($receipt.files).Count -ne 1){throw 'Incomplete DNS inventory.'}
    $entry=$receipt.files[0]
    if($entry.name -cne 'OBSERVATION.json' -or $entry.bytes -lt 0 -or $entry.bytes -gt 131072 -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Unsafe DNS export file.'}
    $path=Join-Path $OutputDirectory $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'DNS observation hash mismatch.'}
    $result=Read-RIJson $path 131072
    foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){if($result.$key -cne $build.$key){throw 'DNS observation provenance mismatch.'}}
    if($result.schema -ne 1 -or $result.case -cne $receipt.case -or $result.probe -cne ('nomad-'+$receipt.token+'-'+$receipt.case.ToLowerInvariant()+'.example.com') -or $result.status -cnotin @('inconclusive','classic_or_system_target_attempt_observed','secure_query_response_observed','failed_doh_no_plain_attempt_in_capture')){throw 'DNS observation scope/status mismatch.'}
    foreach($key in @('secure_response_observed','failed_doh_transaction_observed','plain_target_attempt_observed','all_packet_leak_absence_proven','saved_test_dns_matches')){if($result.$key -isnot [bool]){throw 'DNS observation has untyped assertions.'}}
    foreach($key in @('target_transactions','correlated_doh_attempts','raw_capture_bytes')){if(-not(Test-DnsInteger $result.$key) -or $result.$key -lt 0 -or $result.$key -gt 33554432){throw 'Invalid DNS observation count.'}}
    if($result.raw_capture_sha256 -cnotmatch '^[A-F0-9]{64}$' -or @($result.selected_events).Count -gt 256){throw 'Invalid raw-reference/selected-event budget.'}
    if($result.status -ceq 'classic_or_system_target_attempt_observed' -and -not $result.plain_target_attempt_observed){throw 'Inconsistent plain DNS result.'}
    if($result.all_packet_leak_absence_proven){throw 'DNS packet-absence claim is unsupported.'}
    if($result.status -ceq 'secure_query_response_observed' -and ($receipt.case -cne 'Baseline' -or -not $result.secure_response_observed -or $result.plain_target_attempt_observed)){throw 'Inconsistent secure response result.'}
    if($result.status -ceq 'failed_doh_no_plain_attempt_in_capture' -and ($receipt.case -cne 'Failure' -or -not $result.failed_doh_transaction_observed -or $result.secure_response_observed -or $result.plain_target_attempt_observed)){throw 'Inconsistent failure result.'}
    $postRestore=$false
    if($result.PSObject.Properties['transport_fixture']){
        if($receipt.case -cne 'Failure' -or -not $result.saved_test_dns_matches){throw 'Invalid controlled transport fixture.'}
        if($result.transport_fixture -ceq 'owned-browser-https-block'){
            if($result.firewall_rules_verified -isnot [bool] -or -not $result.firewall_rules_verified -or $result.firewall_profiles_enabled -isnot [bool] -or -not $result.firewall_profiles_enabled){throw 'Invalid active transport fixture.'}
        }elseif($result.transport_fixture -ceq 'restored-before-collection'){
            foreach($key in @('collection_after_restore','current_rules_absent','historical_start_checks_recorded','qualified_fault_fixture','rules_during_capture_rechecked')){if($result.$key -isnot [bool]){throw 'Untyped restored-capture assertion.'}}
            if(-not $result.collection_after_restore -or -not $result.current_rules_absent -or -not $result.historical_start_checks_recorded -or $result.qualified_fault_fixture -or $result.rules_during_capture_rechecked){throw 'Post-restore capture claims active fault qualification.'}
            if($build.original_fault_manifest_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $result.original_fault_manifest_sha256 -cne $build.original_fault_manifest_sha256){throw 'Original fault provenance differs.'}
            if($result.PSObject.Properties['firewall_rules_verified'] -or $result.PSObject.Properties['firewall_profiles_enabled']){throw 'Post-restore capture mixes historical and active-rule assertions.'}
            $postRestore=$true
        }else{throw 'Unknown transport fixture.'}
        foreach($attempt in @($result.selected_events | Where-Object event -CEQ 'DNS_TRANSACTION_HTTPS_ATTEMPT')){if($attempt.endpoint -cne 'https://dns.quad9.net/dns-query'){throw 'Transport fixture resolver differs.'}}
        if($result.browser_image_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $result.browser_module_sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Missing transport browser identity.'}
    }
    $correctionVerified=$false
    if($result.PSObject.Properties['analysis_correction_sha256'] -or $receipt.PSObject.Properties['analysis_correction_sha256']){
        if($result.analysis_correction_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $result.analysis_correction_sha256 -cne $receipt.analysis_correction_sha256){throw 'Correction receipt/result mismatch.'}
        $correctionRoot=Join-Path $InputDirectory 'DnsCorrection';$correctionPath=Join-Path $correctionRoot 'CORRECTION-MANIFEST.json';Assert-RIPlain $correctionPath
        if((Get-FileHash -LiteralPath $correctionPath).Hash -cne $result.analysis_correction_sha256){throw 'Correction manifest changed.'}
        $correction=Read-RIJson $correctionPath 16384
        if($correction.schema -ne 1 -or $correction.original_source_tree_sha256 -cne $build.source_tree_sha256){throw 'Correction scope differs.'}
        $correctionNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach($file in $correction.files){
            if($file.name -cnotin @('Analyze-Dns-NetLog.ps1','Recollect-Dns-Baseline.ps1') -or -not $correctionNames.Add($file.name)){throw 'Unexpected correction inventory.'}
            $correctionFile=Join-Path $correctionRoot $file.name;Assert-RIPlain $correctionFile
            if((Get-Item -LiteralPath $correctionFile).Length -ne $file.bytes -or (Get-FileHash -LiteralPath $correctionFile).Hash -cne $file.sha256){throw 'Correction input changed.'}
        }
        if($correctionNames.Count -ne 2 -or $result.original_identity_refusal -isnot [bool] -or -not(Test-DnsInteger $result.negative_source_events) -or $result.negative_source_events -lt 0 -or $result.negative_source_events -gt 200000){throw 'Invalid correction diagnostic claims.'}
        $correctionVerified=$true
    }
    [pscustomobject]@{hashes_verified=$true;files_verified=1;post_restore_capture=$postRestore;correction_inputs_verified=$correctionVerified;observation_status=$result.status;saved_test_dns_matches=$result.saved_test_dns_matches;raw_capture_independently_verified=$false;scope='Selected copied bytes and guest DNS observations; raw log not exported; no total leak-absence or release qualification'}
}

function Test-DnsRestoreExport([string]$InputDirectory,[string]$OutputDirectory){
    $build=Read-RIJson (Join-Path $InputDirectory 'BUILD-MANIFEST.json');$receipt=Read-RIJson (Join-Path $OutputDirectory 'GUEST-RECEIPT.json') 16384
    if($build.schema -ne 1 -or $build.target -cne 'x86_64-pc-windows-msvc' -or $receipt.schema -ne 1 -or $receipt.case -cne 'Restore' -or $receipt.token -cnotmatch '^[a-f0-9]{32}$' -or $receipt.session_token -cnotmatch '^[a-f0-9]{32}$' -or $receipt.export_token -cnotmatch '^[a-f0-9]{32}$' -or (Split-Path -Leaf $OutputDirectory) -cne ('restore-'+$receipt.token+'-'+$receipt.export_token)){throw 'Invalid DNS restoration receipt scope.'}
    $names=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($entry in $build.input_files){
        if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $names.Add($entry.name)){throw 'Invalid restoration input inventory.'}
        $path=Join-Path $InputDirectory $entry.name;Assert-RIPlain $path
        if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Restoration input changed.'}
    }
    if($names.Count -ne 4 -or (Get-FileHash -LiteralPath (Join-Path $InputDirectory 'Nomad-Helium.exe')).Hash -cne $build.launcher_sha256 -or @($receipt.files).Count -ne 1){throw 'Incomplete restoration input/evidence inventory.'}
    $entry=$receipt.files[0]
    if($entry.name -cne 'RESTORE.json' -or -not(Test-DnsInteger $entry.bytes) -or $entry.bytes -lt 0 -or $entry.bytes -gt 16384 -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Unsafe restoration file.'}
    $path=Join-Path $OutputDirectory $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Restoration file hash mismatch.'}
    $result=Read-RIJson $path 16384
    foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){if($receipt.$key -cne $build.$key -or $result.$key -cne $build.$key){throw 'Restoration provenance mismatch.'}}
    if($result.schema -ne 1 -or $result.token -cne $receipt.token -or $result.session_token -cne $receipt.session_token -or -not(Test-DnsInteger $result.owned_rules_remaining) -or $result.owned_rules_remaining -ne 0 -or $result.config_restored -isnot [bool] -or -not $result.config_restored -or $result.saved_secure_quad9 -isnot [bool] -or -not $result.saved_secure_quad9 -or $result.original_config_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $result.original_config_sha256 -cne $result.observed_config_sha256){throw 'Inconsistent restoration observations.'}
    [pscustomobject]@{hashes_verified=$true;files_verified=1;guest_reports_owned_rules_absent=$true;guest_reports_config_restored=$true;guest_reports_saved_secure_quad9=$true;live_guest_firewall_independently_replayed=$false;scope='Selected restoration copy/provenance and typed guest assertions only; not live host firewall/traffic replay'}
}
