targetScope = 'resourceGroup'

@description('Resource ID of the Log Analytics workspace Sentinel is enabled on.')
param workspaceResourceId string

@description('Deployment location. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Tags applied to every rule, so cost and ownership are attributable.')
param tags object = {}

// Azure Verified Module. Pin the version: an unpinned module is an unreviewed
// change to production collection the next time the pipeline runs.
module dcrWindowsSecurity 'br/public:avm/res/insights/data-collection-rule:0.11.0' = {
  name: 'dcr-windows-security-baseline'
  params: {
    name: 'dcr-windows-security-baseline'
    location: location
    tags: tags
    dataCollectionRuleProperties: {
      kind: 'Windows'
      dataSources: {
        windowsEventLogs: [
          {
            name: 'securityBaseline'
            streams: [ 'Microsoft-SecurityEvent' ]
            // XPath selectors live in their own file so a reviewer sees the real
            // diff when an event ID is added, not a one-line JSON blob.
            xPathQueries: loadJsonContent('../xpath/security-minimal.json')
          }
        ]
      }
      destinations: {
        logAnalytics: [
          { name: 'sentinelWorkspace', workspaceResourceId: workspaceResourceId }
        ]
      }
      dataFlows: [
        {
          streams: [ 'Microsoft-SecurityEvent' ]
          destinations: [ 'sentinelWorkspace' ]
          outputStream: 'Microsoft-SecurityEvent'
        }
      ]
    }
  }
}

module dcrWindowsSysmon 'br/public:avm/res/insights/data-collection-rule:0.11.0' = {
  name: 'dcr-windows-sysmon-operational'
  params: {
    name: 'dcr-windows-sysmon-operational'
    location: location
    tags: tags
    dataCollectionRuleProperties: {
      kind: 'Windows'
      dataSources: {
        windowsEventLogs: [
          {
            name: 'sysmonOperational'
            streams: [ 'Microsoft-Event' ]
            xPathQueries: loadJsonContent('../xpath/sysmon-operational.json')
          }
        ]
      }
      destinations: {
        logAnalytics: [
          { name: 'sentinelWorkspace', workspaceResourceId: workspaceResourceId }
        ]
      }
      dataFlows: [
        {
          streams: [ 'Microsoft-Event' ]
          destinations: [ 'sentinelWorkspace' ]
          // Drop loopback network connections before they are billed.
          transformKql: 'source | where not(Provider == \'Microsoft-Windows-Sysmon\' and EventID == 3 and isnotempty(EventData) and tostring(parse_xml(RawEventData)) has \'127.0.0.1\')'
          // Sysmon lands in WindowsEvent, not SecurityEvent. This catches people out.
          outputStream: 'Microsoft-WindowsEvent'
        }
      ]
    }
  }
}

module dcrLinuxSyslog 'br/public:avm/res/insights/data-collection-rule:0.11.0' = {
  name: 'dcr-linux-syslog-baseline'
  params: {
    name: 'dcr-linux-syslog-baseline'
    location: location
    tags: tags
    dataCollectionRuleProperties: {
      kind: 'Linux'
      dataSources: {
        syslog: [
          {
            name: 'authBaseline'
            streams: [ 'Microsoft-Syslog' ]
            facilityNames: [ 'auth', 'authpriv' ]
            logLevels: [ 'Info', 'Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency' ]
          }
          {
            name: 'systemBaseline'
            streams: [ 'Microsoft-Syslog' ]
            facilityNames: [ 'daemon', 'cron', 'kern', 'syslog' ]
            logLevels: [ 'Warning', 'Error', 'Critical', 'Alert', 'Emergency' ]
          }
        ]
      }
      destinations: {
        logAnalytics: [
          { name: 'sentinelWorkspace', workspaceResourceId: workspaceResourceId }
        ]
      }
      dataFlows: [
        {
          streams: [ 'Microsoft-Syslog' ]
          destinations: [ 'sentinelWorkspace' ]
          transformKql: 'source | where not(SyslogMessage has_any (\'CRON[\', \'session opened for user root by (uid=0)\'))'
          outputStream: 'Microsoft-Syslog'
        }
      ]
    }
  }
}

output dcrWindowsSecurityId string = dcrWindowsSecurity.outputs.resourceId
output dcrWindowsSysmonId string = dcrWindowsSysmon.outputs.resourceId
output dcrLinuxSyslogId string = dcrLinuxSyslog.outputs.resourceId
