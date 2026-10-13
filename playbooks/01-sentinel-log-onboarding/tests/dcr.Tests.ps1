#Requires -Modules Pester

<#
    Semantic checks that Azure will not do for you, and that a portal deployment
    cannot do at all. These run before `az deployment group create`, so a rule
    that would silently fail is caught in the pull request instead of in
    production three weeks later.

    There is no test or dry-run API for DCR transformations. These tests check
    structure and limits, not whether the KQL produces the output you intended.
    That still needs a sample file and a real deployment to a test workspace.
#>

Describe 'DCR semantics' {

    BeforeAll {
        $dcrs = Get-ChildItem $PSScriptRoot/../dcr -Filter *.json -Recurse | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Json = Get-Content $_ -Raw | ConvertFrom-Json
            }
        }
    }

    It '<Name> declares a supported kind' -ForEach $dcrs {
        $Json.kind | Should -BeIn @(
            'Direct', 'AgentSettings', 'Linux', 'PlatformTelemetry', 'Windows', 'WorkspaceTransforms'
        )
    }

    It '<Name> has at most 10 data sources' -ForEach $dcrs {
        if ($Json.properties.dataSources) {
            ($Json.properties.dataSources.PSObject.Properties.Value | Measure-Object).Count |
                Should -BeLessOrEqual 10
        }
    }

    It '<Name> has at most 20 data flows' -ForEach $dcrs {
        ($Json.properties.dataFlows | Measure-Object).Count | Should -BeLessOrEqual 20
    }

    It '<Name> keeps every transformation under 15360 characters' -ForEach $dcrs {
        foreach ($flow in $Json.properties.dataFlows) {
            if ($flow.transformKql) {
                $flow.transformKql.Length | Should -BeLessThan 15360
            }
        }
    }

    It '<Name> never sets both transform and transformKql on one data flow' -ForEach $dcrs {
        foreach ($flow in $Json.properties.dataFlows) {
            ($flow.transform -and $flow.transformKql) | Should -BeFalse
        }
    }

    It '<Name> uses only Microsoft- or Custom- stream prefixes' -ForEach $dcrs {
        foreach ($flow in $Json.properties.dataFlows) {
            foreach ($s in $flow.streams) {
                $s | Should -Match '^(Microsoft|Custom)-'
            }
        }
    }

    It '<Name> uses no join or summarize in a transformation' -ForEach $dcrs {
        # Transformation KQL is a strict subset. Both of these parse in the editor
        # and fail at deployment, which is a slow way to learn.
        foreach ($flow in $Json.properties.dataFlows) {
            if ($flow.transformKql) {
                $flow.transformKql | Should -Not -Match '\|\s*(join|summarize)\s'
            }
        }
    }

    It '<Name> declares every stream it routes' -ForEach $dcrs {
        if ($Json.properties.streamDeclarations) {
            $declared = $Json.properties.streamDeclarations.PSObject.Properties.Name
            foreach ($flow in $Json.properties.dataFlows) {
                foreach ($s in $flow.streams) {
                    if ($s -like 'Custom-*') {
                        $declared | Should -Contain $s
                    }
                }
            }
        }
    }

    It '<Name> gives every Direct rule a TimeGenerated column' -ForEach $dcrs {
        # The Logs Ingestion API requires it and nothing downstream will invent it.
        if ($Json.kind -eq 'Direct') {
            foreach ($decl in $Json.properties.streamDeclarations.PSObject.Properties) {
                $decl.Value.columns.name | Should -Contain 'TimeGenerated'
            }
        }
    }

    It '<Name> keeps a Direct rule name within 30 characters' -ForEach $dcrs {
        # kind: Direct caps the DCR name at 30 characters. DCE-based rules allow 64.
        if ($Json.kind -eq 'Direct') {
            ($Name -replace '\.json$', '').Length | Should -BeLessOrEqual 30
        }
    }
}
