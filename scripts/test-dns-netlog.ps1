# Offline authored DNS events only; no browser, resolver, packet capture or profile writes.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sandbox-network/Analyze-Dns-NetLog.ps1')
function Refuse([scriptblock]$Action){$failed=$false;try{& $Action | Out-Null}catch{$failed=$true};if(-not $failed){throw 'Invalid fixture accepted.'}}
function Event([int]$Type,[int]$Source,[int]$Phase,$Parameters){[pscustomobject]@{type=$Type;phase=$Phase;source=[pscustomobject]@{id=$Source};params=[pscustomobject]$Parameters}}
function Fixture([string]$Probe,[string]$Endpoint,[int]$Error=0,[int]$Rcode=0){
    $types=[pscustomobject]@{DNS_TRANSACTION=101;DNS_TRANSACTION_QUERY=102;DNS_TRANSACTION_HTTPS_ATTEMPT=103;DNS_TRANSACTION_RESPONSE=104;URL_REQUEST_START_JOB=105;DNS_TRANSACTION_ATTEMPT=106;HOST_RESOLVER_SYSTEM_TASK=107;DNS_CONFIG_CHANGED=108}
    $events=@((Event 108 0 0 @{}),(Event 101 1 1 @{hostname=$Probe}),(Event 103 1 0 @{source_dependency=@{id=2}}),(Event 105 2 1 @{url=$Endpoint}))
    if($Error -cin @(0,-105)){$events+=Event 104 1 0 @{source_dependency=@{id=2};rcode=$Rcode;answer_count=1;response_buffer='PRIVATE RAW MUST NOT EXPORT'}}
    $events+=Event 101 1 2 @{net_error=$Error}
    [pscustomobject]@{constants=[pscustomobject]@{logEventTypes=$types;logEventPhase=[pscustomobject]@{PHASE_NONE=0;PHASE_BEGIN=1;PHASE_END=2}};events=$events}
}
$probe='nomad-'+('a'*32)+'-baseline.example.com'
$valid=Fixture $probe 'https://dns.quad9.net/dns-query?dns=PUBLIC_QUERY'
$result=Get-DnsObservation $valid $probe Baseline
if($result.status -cne 'secure_query_response_observed' -or $result.all_packet_leak_absence_proven -or ($result | ConvertTo-Json -Depth 15) -match 'PRIVATE RAW|PUBLIC_QUERY'){throw 'Correlated result/privacy filter failed.'}
# Production reads JSON; cover round-trips on both PowerShell JSON implementations.
$roundTrip=ConvertFrom-Json -InputObject ($valid | ConvertTo-Json -Depth 20)
if((Get-DnsObservation $roundTrip $probe Baseline).status -cne 'secure_query_response_observed'){throw 'JSON-round-trip response not recognized.'}
$partitioned=Fixture $probe 'https://dns.quad9.net/dns-query'
foreach($e in $partitioned.events){if($e.source.id -eq 1){$e.source.id=-2147483647}elseif($e.source.id -eq 2){$e.source.id=-2147483646};if($e.params.PSObject.Properties['source_dependency']){$e.params.source_dependency.id=-2147483646}}
$partitioned=ConvertFrom-Json -InputObject ($partitioned | ConvertTo-Json -Depth 20)
if((Get-DnsObservation $partitioned $probe Baseline).status -cne 'secure_query_response_observed'){throw 'Signed source partition not correlated.'}
$unrelatedNegative=Fixture $probe 'https://dns.quad9.net/dns-query';$unrelatedNegative.events[0].source.id=-2147483647
if((Get-DnsObservation $unrelatedNegative $probe Baseline).status -cne 'secure_query_response_observed'){throw 'Unrelated signed-source event rejected.'}
foreach($invalidId in @('1',1.5,[long]2147483648,[long]-2147483649)){$bad=Fixture $probe 'https://dns.quad9.net/dns-query';$bad.events[1].source.id=$invalidId;Refuse {Get-DnsObservation $bad $probe Baseline}}
$bad=Fixture $probe 'https://dns.quad9.net/dns-query';$bad.events[1].source.id=0;Refuse {Get-DnsObservation $bad $probe Baseline}
$nx=Fixture $probe 'https://dns.quad9.net/dns-query' -105 3
if((Get-DnsObservation $nx $probe Baseline).status -cne 'secure_query_response_observed'){throw 'Valid DoH negative response not recognized.'}
$unrelated=Fixture $probe 'https://dns.quad9.net/dns-query';$unrelated.events[3].source.id=99
if((Get-DnsObservation $unrelated $probe Baseline).secure_response_observed){throw 'Unrelated endpoint credited.'}
$wrong=Fixture $probe 'https://other.invalid/dns-query'
if((Get-DnsObservation $wrong $probe Baseline).secure_response_observed){throw 'Wrong resolver credited.'}
$redirect=Fixture $probe 'https://dns.quad9.net/dns-query';$redirect.events+=Event 105 2 1 @{url='https://other.invalid/dns-query'}
if((Get-DnsObservation $redirect $probe Baseline).secure_response_observed){throw 'Changed resolver endpoint credited.'}
$plain=Fixture $probe 'https://dns.quad9.net/dns-query';$plain.events+=Event 106 1 0 @{source_dependency=@{id=50}}
if((Get-DnsObservation $plain $probe Baseline).status -cne 'classic_or_system_target_attempt_observed'){throw 'Plain fallback hidden.'}
$system=Fixture $probe 'https://dns.quad9.net/dns-query';$system.events+=Event 107 60 1 @{hostname=$probe}
if(-not (Get-DnsObservation $system $probe Baseline).plain_target_attempt_observed){throw 'System resolver attempt hidden.'}
$failureProbe='nomad-'+('a'*32)+'-failure.example.com'
$failure=Fixture $failureProbe 'https://127.0.0.1:9/dns-query' -118
if((Get-DnsObservation $failure $failureProbe Failure).status -cne 'failed_doh_no_plain_attempt_in_capture'){throw 'Failed DoH fixture not recognized.'}
$empty=[pscustomobject]@{constants=$valid.constants;events=@()}
if((Get-DnsObservation $empty $probe Baseline).status -cne 'inconclusive'){throw 'Empty evidence became success.'}
Refuse {Get-DnsObservation $valid 'private.invalid' Baseline}
Refuse {Get-DnsObservation $valid $probe Failure}
$bad=Fixture $probe 'https://dns.quad9.net/dns-query';$bad.events[0].type='108';Refuse {Get-DnsObservation $bad $probe Baseline}
$bad=Fixture $probe 'https://dns.quad9.net/dns-query';$bad.constants.logEventTypes.DNS_TRANSACTION_QUERY=101;Refuse {Get-DnsObservation $bad $probe Baseline}
$bad=Fixture $probe 'https://dns.quad9.net/dns-query';$bad.events[4].params.rcode='0'
if((Get-DnsObservation $bad $probe Baseline).secure_response_observed){throw 'String response fields credited.'}
$quad9Failure=Fixture $failureProbe 'https://dns.quad9.net/dns-query' -138
if((Get-DnsObservation $quad9Failure $failureProbe Failure Quad9Blocked).status -cne 'failed_doh_no_plain_attempt_in_capture'){throw 'Quad9 transport failure not recognized.'}
if((Get-DnsObservation $quad9Failure $failureProbe Failure).status -cne 'inconclusive'){throw 'Quad9 mislabeled as loopback fault.'}
$quad9Failure.events+=Event 106 1 0 @{}
if((Get-DnsObservation $quad9Failure $failureProbe Failure Quad9Blocked).status -cne 'classic_or_system_target_attempt_observed'){throw 'Transport fault fallback hidden.'}
Refuse {Get-DnsObservation $valid $probe Baseline Quad9Blocked}
$faultRunner=Join-Path $PSScriptRoot 'sandbox-network/Run-Dns-Transport-Fault.ps1'
$tokens=$null;$errors=$null;$faultAst=[Management.Automation.Language.Parser]::ParseFile($faultRunner,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$recoveryRunner=Join-Path $PSScriptRoot 'sandbox-network/Recover-Restored-Dns-Capture.ps1'
$tokens=$null;$errors=$null;$recoveryAst=[Management.Automation.Language.Parser]::ParseFile($recoveryRunner,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Restored capture-recovery syntax failure.'}
$refused=$false;try{& $recoveryRunner}catch{if($_.Exception.Message -ceq 'Disposable post-restore capture recovery only.'){$refused=$true}}
if(-not $refused){throw 'Restored capture-recovery host guard failed.'}
if($recoveryAst.Find({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -cin @('Start-Process','Stop-Process','New-NetFirewallRule','Remove-NetFirewallRule','Set-NetFirewallRule','Set-NetFirewallProfile','Set-TestDns','Invoke-WebRequest','Invoke-RestMethod','Save-FaultJson')},$true)){throw 'Post-restore recovery has forbidden live-state mutations.'}
$guardRefused=$false;try{& $faultRunner}catch{if($_.Exception.Message -ceq 'Disposable DNS-fault Sandbox only; no host firewall or profile actions.'){$guardRefused=$true}}
if(-not $guardRefused){throw 'Transport-fault host guard did not refuse.'}
if($faultAst.Find({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -cin @('Set-NetFirewallProfile','Set-NetFirewallRule','Invoke-WebRequest','Invoke-RestMethod','Stop-Process','Set-TestDns')},$true)){throw 'Transport fault has forbidden global/provision/profile/process mutations.'}
# Continuation must retain the guarded mutation functions but cannot provision Fresh.
$continuation=Join-Path $PSScriptRoot 'sandbox-network/Continue-Helium-Dns.ps1'
$tokens=$null;$errors=$null;$continuationAst=[Management.Automation.Language.Parser]::ParseFile($continuation,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Continuation syntax error.'}
if($continuationAst.Find({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -cin @('Invoke-RestMethod','Invoke-WebRequest','Copy-Item')},$true)){throw 'Continuation must not provision.'}
$tokens=$null;$errors=$null;$originalAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'sandbox-network/Run-Helium-Dns.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Write-DnsConfig','Get-DnsBrowsers','Get-DnsLocal','Set-TestDns','Start-DnsLauncher')){
    $original=$originalAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    $continued=$continuationAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    if($null -eq $continued -or $original.Extent.Text -cne $continued.Extent.Text){throw 'Continuation changed validated safety functions.'}
}
$guardRefused=$false
try{& $continuation}catch{if($_.Exception.Message -ceq 'Disposable Sandbox only; no host DNS/profile changes.'){$guardRefused=$true}}
if(-not $guardRefused){throw 'Continuation host guard did not refuse.'}
# Parse workflow syntax and test only its config-data function with temporary/mocked dependencies.
$runner=Join-Path $PSScriptRoot 'sandbox-network/Run-Helium-Dns.ps1'
foreach($file in @($runner,(Join-Path $PSScriptRoot 'prepare-helium-dns-sandbox.ps1'),(Join-Path $PSScriptRoot 'sandbox-network/Inspect-Dns-Capture.ps1'),(Join-Path $PSScriptRoot 'sandbox-network/Recollect-Dns-Baseline.ps1'))){$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors | Out-String)}}
. (Join-Path $PSScriptRoot 'sandbox-recovery/Recovery-Integration-Helpers.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('nomad-dns-data-'+[Guid]::NewGuid().ToString('N'))
try{
    $null=New-Item -ItemType Directory -Path $root
    & {
        $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
        $definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-DnsConfig'},$true)
        . ([scriptblock]::Create($definition.Extent.Text))
        $instance=$root;$configPath=Join-Path $root 'nomad.toml';$statePath=Join-Path $root 'state.json';$utf8=New-Object Text.UTF8Encoding($false)
        $state=[pscustomobject]@{token=('a'*32);case='Baseline';config_sha256=''}
        function Save-DnsJson([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 10),$utf8)}
        Write-DnsConfig Baseline $true
        $text=[IO.File]::ReadAllText($configPath);$match=[regex]::Match($text,'(?m)^extra_args = (.+)$')
        $argsData=ConvertFrom-Json -InputObject $match.Groups[1].Value
        if($argsData.Count -ne 3 -or $argsData[0] -cne ('--log-net-log='+$root+'\Baseline.netlog.json') -or $argsData[1] -cne '--net-log-capture-mode=Default' -or $argsData[2] -cne ('https://nomad-'+('a'*32)+'-baseline.example.com/')){throw 'Browser arguments were not separate literal data.'}
        [IO.File]::WriteAllText((Join-Path $root 'Baseline.netlog.json'),'existing raw capture',$utf8)
        Refuse {Write-DnsConfig Baseline $true}
    }
    & {
        $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
        $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Set-TestDns'},$true)
        . ([scriptblock]::Create($definition.Extent.Text))
        $script:mockRunning=$false;$script:mockWrites=0
        $script:mockLocal=[pscustomobject]@{dns_over_https=[pscustomobject]@{mode='secure';templates='https://dns.quad9.net/dns-query'};unrelated_choice='preserve'}
        $localPath=Join-Path $root 'authored-local-state.json'
        function Get-DnsBrowsers {if($script:mockRunning){return 123}}
        function Get-DnsLocal {return $script:mockLocal}
        function Save-DnsJson([string]$Path,$Value){$script:mockWrites++}
        $script:mockRunning=$true
        Refuse {Set-TestDns 'https://dns.quad9.net/dns-query' 'https://127.0.0.1:9/dns-query'}
        $script:mockRunning=$false;$script:mockLocal.dns_over_https.templates='https://user-choice.invalid/dns-query'
        Refuse {Set-TestDns 'https://dns.quad9.net/dns-query' 'https://127.0.0.1:9/dns-query'}
        if($script:mockWrites){throw 'Refused DNS cases wrote profile data.'}
        $script:mockLocal.dns_over_https.templates='https://dns.quad9.net/dns-query'
        Set-TestDns 'https://dns.quad9.net/dns-query' 'https://127.0.0.1:9/dns-query'
        Set-TestDns 'https://127.0.0.1:9/dns-query' 'https://dns.quad9.net/dns-query'
        if($script:mockWrites -ne 2 -or $script:mockLocal.unrelated_choice -cne 'preserve' -or $script:mockLocal.dns_over_https.templates -cne 'https://dns.quad9.net/dns-query'){throw 'Owned resolver restoration/preservation failed.'}
    }
    # Native firewall commands are LOCAL MOCKS. Only inert files in the owned temp tree.
    & {
        foreach($name in @('Assert-FaultRule','Get-FaultRules','Restore-Fault')){
            $definition=$faultAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        $token=('a'*32);$image='C:\NomadDnsQualification\'+('b'*32)+'\Instance\Browser\chrome.exe'
        $script:mockRules=@{};$script:mockPorts=@{};$script:removed=0;$script:saved=0;$script:running=$false
        foreach($protocol in @('TCP','UDP')){
            $name='NomadDnsFault-'+$token+'-'+$protocol
            $script:mockRules[$name]=[pscustomobject]@{Name=$name;Description=('Nomad disposable DNS fault '+$token);Direction='Outbound';Action='Block';Enabled='True';Profile='Any'}
            $script:mockPorts[$name]=[pscustomobject]@{Protocol=if($protocol -ceq 'TCP'){'6'}else{'17'};RemotePort='443';LocalPort='Any'}
        }
        function Get-NetFirewallRule {[CmdletBinding()]param([string]$PolicyStore) return @($script:mockRules.Values)}
        function Get-NetFirewallApplicationFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule) process{[pscustomobject]@{Program=$image}}}
        function Get-NetFirewallPortFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule) process{$script:mockPorts[$Rule.Name]}}
        function Get-NetFirewallAddressFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule) process{[pscustomobject]@{RemoteAddress='Any';LocalAddress='Any'}}}
        function Remove-NetFirewallRule {[CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$Rule) process{$script:removed++;$script:mockRules.Remove($Rule.Name)}}
        function Assert-FaultClosed {if($script:running){throw 'authored running browser refusal'}}
        function Assert-FaultDns {}
        function Save-FaultJson([string]$Path,$Value){$script:saved++}
        $configPath=Join-Path $root 'fault-config.toml';$backupPath=Join-Path $root 'fault-backup.toml';$statePath=Join-Path $root 'fault-state.json'
        [IO.File]::WriteAllText($configPath,'fault');[IO.File]::WriteAllText($backupPath,'original')
        $state=[pscustomobject]@{token=$token;original_config_sha256=(Get-FileHash -LiteralPath $backupPath).Hash;fault_config_sha256=(Get-FileHash -LiteralPath $configPath).Hash;restored=$false}
        $rules=@(Get-FaultRules);if($rules.Count -ne 2){throw 'Authored exact rule inventory failed.'}
        $rule=$script:mockRules['NomadDnsFault-'+$token+'-TCP'];$app=[pscustomobject]@{Program=$image};$port=$script:mockPorts[$rule.Name];$addr=[pscustomobject]@{RemoteAddress='Any';LocalAddress='Any'}
        $app.Program='C:\Unrelated\chrome.exe';Refuse {Assert-FaultRule $rule $app $port $addr $rule.Name $image TCP $token};$app.Program=$image
        $port.RemotePort='53';Refuse {Assert-FaultRule $rule $app $port $addr $rule.Name $image TCP $token};$port.RemotePort='443'
        $rule.Description='foreign';Refuse {Assert-FaultRule $rule $app $port $addr $rule.Name $image TCP $token};$rule.Description='Nomad disposable DNS fault '+$token
        $rule.Direction='Inbound';Refuse {Assert-FaultRule $rule $app $port $addr $rule.Name $image TCP $token};$rule.Direction='Outbound'
        $script:mockPorts['NomadDnsFault-'+$token+'-UDP'].RemotePort='53'
        Refuse {Restore-Fault};if($script:removed -ne 0){throw 'Partial deletion preceded full rule validation.'}
        $script:mockPorts['NomadDnsFault-'+$token+'-UDP'].RemotePort='443'
        $script:running=$true;Refuse {Restore-Fault};$script:running=$false
        [IO.File]::WriteAllText($configPath,'user changed config');Refuse {Restore-Fault}
        if($script:removed -ne 0 -or $script:saved -ne 0){throw 'Refused restore mutated authored state.'}
        [IO.File]::WriteAllText($configPath,'fault');Restore-Fault
        if($script:removed -ne 2 -or $script:mockRules.Count -ne 0 -or -not $state.restored -or [IO.File]::ReadAllText($configPath) -cne 'original'){throw 'Owned rule/config restore failed.'}
        Restore-Fault
        if($script:removed -ne 2){throw 'Repeated restore removed extra rules.'}
    }
    # Authored metadata and inert launcher bytes; verifier does not execute inputs.
    $inputs=Join-Path $root 'Input';$null=New-Item -ItemType Directory -Path $inputs
    $utf8=New-Object Text.UTF8Encoding($false)
    $names=@('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1')
    $inventory=@(foreach($name in $names){$path=Join-Path $inputs $name;[IO.File]::WriteAllText($path,'inert authored input',$utf8);@{name=$name;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash}})
    $build=@{schema=1;target='x86_64-pc-windows-msvc';base_commit=('a'*40);source_tree_sha256=('B'*64);launcher_sha256=(Get-FileHash -LiteralPath (Join-Path $inputs 'Nomad-Helium.exe')).Hash;input_files=$inventory}
    [IO.File]::WriteAllText((Join-Path $inputs 'BUILD-MANIFEST.json'),($build|ConvertTo-Json -Depth 10),$utf8)
    $out=Join-Path $root ('baseline-'+('a'*32)+'-'+('b'*32));$null=New-Item -ItemType Directory -Path $out
    $observation=Get-DnsObservation $valid $probe Baseline
    foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){$observation|Add-Member -NotePropertyName $key -NotePropertyValue $build[$key]}
    $observation|Add-Member -NotePropertyName saved_test_dns_matches -NotePropertyValue $true
    $observation|Add-Member -NotePropertyName raw_capture_sha256 -NotePropertyValue ('C'*64)
    $observation|Add-Member -NotePropertyName raw_capture_bytes -NotePropertyValue 2000
    $receipt=@{schema=1;case='Baseline';token=('a'*32);export_token=('b'*32);base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256;files=@()}
    function Write-FixtureExport {
        $path=Join-Path $out 'OBSERVATION.json';[IO.File]::WriteAllText($path,($observation|ConvertTo-Json -Depth 15),$utf8)
        $receipt.files=@(@{name='OBSERVATION.json';bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash})
        [IO.File]::WriteAllText((Join-Path $out 'GUEST-RECEIPT.json'),($receipt|ConvertTo-Json -Depth 10),$utf8)
    }
    Write-FixtureExport
    $verified=Test-DnsEvidenceExport $inputs $out
    if(-not $verified.hashes_verified -or $verified.raw_capture_independently_verified){throw 'Host verifier overstated raw evidence.'}
    $observation.all_packet_leak_absence_proven=$true;Write-FixtureExport;Refuse {Test-DnsEvidenceExport $inputs $out}
    $observation.all_packet_leak_absence_proven=$false;$observation.secure_response_observed='true';Write-FixtureExport;Refuse {Test-DnsEvidenceExport $inputs $out}
    $observation.secure_response_observed=$true;$observation.plain_target_attempt_observed=$true;Write-FixtureExport;Refuse {Test-DnsEvidenceExport $inputs $out}
    $observation.plain_target_attempt_observed=$false;Write-FixtureExport
    [IO.File]::AppendAllText((Join-Path $out 'OBSERVATION.json'),' ',$utf8);Refuse {Test-DnsEvidenceExport $inputs $out}
    Write-FixtureExport
    $faultOut=Join-Path $root ('failure-'+('a'*32)+'-'+('b'*32));$null=New-Item -ItemType Directory -Path $faultOut
    $faultObservation=Get-DnsObservation (Fixture $failureProbe 'https://dns.quad9.net/dns-query' -138) $failureProbe Failure Quad9Blocked
    foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){$faultObservation|Add-Member -NotePropertyName $key -NotePropertyValue $build[$key]}
    foreach($pair in @(@('saved_test_dns_matches',$true),@('firewall_rules_verified',$true),@('firewall_profiles_enabled',$true),@('transport_fixture','owned-browser-https-block'),@('browser_image_sha256',('A'*64)),@('browser_module_sha256',('B'*64)),@('raw_capture_sha256',('C'*64)),@('raw_capture_bytes',2000))){$faultObservation|Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1]}
    $faultReceipt=@{schema=1;case='Failure';token=('a'*32);export_token=('b'*32);base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256;files=@()}
    function Write-FaultFixture {
        $path=Join-Path $faultOut 'OBSERVATION.json';[IO.File]::WriteAllText($path,($faultObservation|ConvertTo-Json -Depth 15),$utf8)
        $faultReceipt.files=@(@{name='OBSERVATION.json';bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash})
        [IO.File]::WriteAllText((Join-Path $faultOut 'GUEST-RECEIPT.json'),($faultReceipt|ConvertTo-Json -Depth 10),$utf8)
    }
    Write-FaultFixture
    if((Test-DnsEvidenceExport $inputs $faultOut).observation_status -cne 'failed_doh_no_plain_attempt_in_capture'){throw 'Controlled transport summary not verified.'}
    $faultObservation.saved_test_dns_matches=$false;Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    $faultObservation.saved_test_dns_matches=$true;$faultObservation.firewall_rules_verified=$false;Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    $faultObservation.firewall_rules_verified=$true;$faultObservation.firewall_profiles_enabled='true';Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    # Post-restore recovery remains explicit about missing active-at-collection checks.
    $faultObservation.PSObject.Properties.Remove('firewall_rules_verified');$faultObservation.PSObject.Properties.Remove('firewall_profiles_enabled')
    $faultObservation.transport_fixture='restored-before-collection'
    foreach($pair in @(@('collection_after_restore',$true),@('current_rules_absent',$true),@('historical_start_checks_recorded',$true),@('qualified_fault_fixture',$false),@('rules_during_capture_rechecked',$false),@('original_fault_manifest_sha256',('D'*64)))){$faultObservation|Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1]}
    $build.original_fault_manifest_sha256=('D'*64)
    [IO.File]::WriteAllText((Join-Path $inputs 'BUILD-MANIFEST.json'),($build|ConvertTo-Json -Depth 10),$utf8)
    Write-FaultFixture
    if(-not(Test-DnsEvidenceExport $inputs $faultOut).post_restore_capture){throw 'Historical capture scope not retained.'}
    $faultObservation.qualified_fault_fixture=$true;Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    $faultObservation.qualified_fault_fixture=$false;$faultObservation.rules_during_capture_rechecked=$true;Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    $faultObservation.rules_during_capture_rechecked=$false;$faultObservation.current_rules_absent='true';Write-FaultFixture;Refuse {Test-DnsEvidenceExport $inputs $faultOut}
    $faultObservation.current_rules_absent=$true
    $restoreOut=Join-Path $root ('restore-'+('a'*32)+'-'+('b'*32));$null=New-Item -ItemType Directory -Path $restoreOut
    $restoreObservation=@{schema=1;token=('a'*32);session_token=('c'*32);owned_rules_remaining=0;config_restored=$true;saved_secure_quad9=$true;original_config_sha256=('E'*64);observed_config_sha256=('E'*64);base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256}
    $restoreReceipt=@{schema=1;case='Restore';token=('a'*32);session_token=('c'*32);export_token=('b'*32);base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256;files=@()}
    function Write-RestoreFixture {
        $path=Join-Path $restoreOut 'RESTORE.json';[IO.File]::WriteAllText($path,($restoreObservation|ConvertTo-Json -Depth 10),$utf8)
        $restoreReceipt.files=@(@{name='RESTORE.json';bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash})
        [IO.File]::WriteAllText((Join-Path $restoreOut 'GUEST-RECEIPT.json'),($restoreReceipt|ConvertTo-Json -Depth 10),$utf8)
    }
    Write-RestoreFixture
    if(-not(Test-DnsRestoreExport $inputs $restoreOut).hashes_verified){throw 'Restoration evidence not checked.'}
    $restoreObservation.owned_rules_remaining=1;Write-RestoreFixture;Refuse {Test-DnsRestoreExport $inputs $restoreOut}
    $restoreObservation.owned_rules_remaining=0;$restoreObservation.config_restored='true';Write-RestoreFixture;Refuse {Test-DnsRestoreExport $inputs $restoreOut}
    $restoreObservation.config_restored=$true;$restoreObservation.observed_config_sha256=('F'*64);Write-RestoreFixture;Refuse {Test-DnsRestoreExport $inputs $restoreOut}
    $restoreObservation.observed_config_sha256=('E'*64);Write-RestoreFixture
    [IO.File]::AppendAllText((Join-Path $restoreOut 'RESTORE.json'),' ',$utf8);Refuse {Test-DnsRestoreExport $inputs $restoreOut}
    $correctionRoot=Join-Path $inputs 'DnsCorrection';$null=New-Item -ItemType Directory -Path $correctionRoot
    $correctionFiles=@(foreach($name in @('Analyze-Dns-NetLog.ps1','Recollect-Dns-Baseline.ps1')){$path=Join-Path $correctionRoot $name;[IO.File]::WriteAllText($path,'inert correction input',$utf8);@{name=$name;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash}})
    $correction=@{schema=1;original_source_tree_sha256=$build.source_tree_sha256;files=$correctionFiles}
    $correctionPath=Join-Path $correctionRoot 'CORRECTION-MANIFEST.json'
    [IO.File]::WriteAllText($correctionPath,($correction|ConvertTo-Json -Depth 10),$utf8)
    $correctionHash=(Get-FileHash -LiteralPath $correctionPath).Hash
    $observation|Add-Member -NotePropertyName analysis_correction_sha256 -NotePropertyValue $correctionHash
    $observation|Add-Member -NotePropertyName original_identity_refusal -NotePropertyValue $true
    $observation|Add-Member -NotePropertyName negative_source_events -NotePropertyValue 3
    $receipt.analysis_correction_sha256=$correctionHash;Write-FixtureExport
    if(-not(Test-DnsEvidenceExport $inputs $out).correction_inputs_verified){throw 'Correction provenance not verified.'}
    [IO.File]::AppendAllText((Join-Path $correctionRoot 'Recollect-Dns-Baseline.ps1'),'changed',$utf8);Refuse {Test-DnsEvidenceExport $inputs $out}
    [IO.File]::WriteAllText((Join-Path $correctionRoot 'Recollect-Dns-Baseline.ps1'),'inert correction input',$utf8)
    $receipt.analysis_correction_sha256=('D'*64);Write-FixtureExport;Refuse {Test-DnsEvidenceExport $inputs $out}
    $receipt.analysis_correction_sha256=$correctionHash;Write-FixtureExport
    [IO.File]::AppendAllText((Join-Path $inputs 'Nomad-Helium.exe'),'changed',$utf8);Refuse {Test-DnsEvidenceExport $inputs $out}
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
    $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Set-TestDns'},$true))
    if($commands.Count -ne 1 -or $commands[0].Extent.Text -cnotmatch "^Set-TestDns 'https://127\.0\.0\.1:9/dns-query' 'https://dns\.quad9\.net/dns-query'$"){throw 'Only known-choice restoration may mutate DNS.'}
    foreach($scriptPath in @($runner,$continuation)){
        $tokens=$null;$errors=$null;$testAst=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
        $branch=$testAst.Find({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith("if(`$Phase -ceq 'FailClosed'){",[StringComparison]::Ordinal)},$true)
        if($null -eq $branch){throw 'Retired fixture refusal is missing.'}
        $body=$branch.Clauses[0].Item2.Extent.Text
        $refused=$false
        try{& ([scriptblock]::Create($body.Substring(1,$body.Length-2)))}catch{if($_.Exception.Message -ceq 'Prelaunch resolver mutation is not a valid outage test: Nomad re-enforces Quad9. Existing captures and restore remain available; do not repeat this fixture.'){$refused=$true}}
        if(-not $refused -or $branch.Find({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){throw 'Retired fixture performed actions instead of refusing.'}
    }
}finally{
    $full=[IO.Path]::GetFullPath($root)
    if(-not $full.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)-or(Split-Path -Leaf $full)-cnotmatch '^nomad-dns-data-[a-f0-9]{32}$'){throw 'Unsafe temporary cleanup.'}
    Assert-RIPlain $full
    if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
Write-Host 'DNS NetLog source-correlation/privacy/failure fixtures passed; actual browser DNS NOT TESTED.'
$global:LASTEXITCODE=0
