// gatehouse -> Microsoft Sentinel: custom table, Logs Ingestion endpoint + DCR, and the
// GH00x analytics rules. Deploy at resource-group scope; see docs/sentinel-setup.md.
//
// Generated inputs (do not edit; run `uv run python -m detections.build_infra`):
//   generated/columns.json  <- detections/schema/GatehouseEvents_CL.json
//   generated/rules.json    <- detections/rules/*.yaml (the rules tested in Kusto)

targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Log Analytics workspace name. Created when createWorkspace is true; otherwise it must already exist in this resource group.')
param workspaceName string

@description('Create the workspace (true) or use an existing one (false).')
param createWorkspace bool = true

@description('Enable Microsoft Sentinel on the workspace (skip if it is already enabled).')
param enableSentinel bool = true

@description('Create the GH00x scheduled analytics rules.')
param deployAnalyticsRules bool = true

@description('Object id of the identity gatehouse authenticates as (user, service principal or managed identity). It gets Monitoring Metrics Publisher on the DCR. Leave empty to assign it yourself.')
param publisherPrincipalId string = ''

@allowed(['User', 'ServicePrincipal', 'Group'])
param publisherPrincipalType string = 'ServicePrincipal'

@minValue(30)
@maxValue(730)
@description('Interactive retention of GatehouseEvents_CL, in days.')
param retentionInDays int = 90

param namePrefix string = 'gatehouse'

var tableName = 'GatehouseEvents_CL'
var streamName = 'Custom-${tableName}'
var columns = loadJsonContent('generated/columns.json')
var rules = loadJsonContent('generated/rules.json')
// Built-in role "Monitoring Metrics Publisher": allows uploads through a DCR.
// https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/monitor
var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

resource newWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createWorkspace) {
  name: workspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
  dependsOn: [newWorkspace]
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: '${namePrefix}-dce'
  location: location
  properties: {
    networkAcls: { publicNetworkAccess: 'Enabled' }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${namePrefix}-dcr'
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': { columns: columns }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'workspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['workspace']
        // gatehouse already redacts and shapes events; nothing to transform.
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [table]
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(publisherPrincipalId)) {
  name: guid(dcr.id, publisherPrincipalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisher)
    principalId: publisherPrincipalId
    principalType: publisherPrincipalType
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = if (enableSentinel) {
  scope: workspace
  name: 'default'
  properties: {}
}

// Rule ids are the GUIDs in the YAML, so a redeploy updates rules instead of duplicating.
resource analyticsRules 'Microsoft.SecurityInsights/alertRules@2024-03-01' = [
  for rule in (deployAnalyticsRules ? rules : []): {
    scope: workspace
    name: rule.id
    kind: 'Scheduled'
    properties: rule.properties
    dependsOn: [sentinel, table]
  }
]

@description('Pass to gatehouse as --sentinel-endpoint / GATEHOUSE_SENTINEL_ENDPOINT.')
output ingestionEndpoint string = dce.properties.logsIngestion.endpoint

@description('Pass to gatehouse as --sentinel-dcr-id / GATEHOUSE_SENTINEL_DCR_ID.')
output dcrImmutableId string = dcr.properties.immutableId

output streamName string = streamName
output workspaceId string = workspace.id
