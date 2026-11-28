// The Sentinel -> gatehouse control loop (D-055): a Storage queue, two Logic App
// playbooks that put control signals on it, and automation rules that run them.
//
//   High-severity incident from a gatehouse rule -> playbook "kill" -> queue
//   Alert from a gatehouse rule with an AgentSessionId -> playbook "lock" -> queue
//   `gatehouse listen` on each machine polls the queue and applies the signal.
//
// The playbooks write with their managed identity (Storage Queue Data Message Sender);
// gatehouse reads with its own identity (Storage Queue Data Message Processor) or a
// user delegation SAS. Shared-key access is off, so no account key exists to leak.

param location string
param workspaceName string
param namePrefix string

@description('Analytics rule resource ids whose incidents and alerts may trigger the playbooks.')
param ruleIds array

@description('Incident severity that engages the kill switch on every listening machine.')
@allowed(['High', 'Medium'])
param killSeverity string = 'High'

@description('Create the lock-session automation rule (alerts). Verify its trigger on first deploy: docs/sentinel-setup.md.')
param lockOnAlerts bool = true

@description('Object id of the identity `gatehouse listen` runs as (Message Processor on the queue). Empty: assign later.')
param listenerPrincipalId string = ''

@allowed(['User', 'ServicePrincipal', 'Group'])
param listenerPrincipalType string = 'ServicePrincipal'

@description('Object id of the "Azure Security Insights" service principal in your tenant: az ad sp show --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 --query id -o tsv. Empty: grant it by hand.')
param securityInsightsPrincipalId string = ''

var queueName = 'gatehouse-control'
var messageSender = 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a' // Storage Queue Data Message Sender
var messageProcessor = '8a0f0c08-91a1-4084-bc3d-661d67233fed' // Storage Queue Data Message Processor
var automationContributor = 'f4c81013-99ee-4d62-a7ee-b3f1f648599a' // Microsoft Sentinel Automation Contributor
var storageName = take('${replace(toLower(namePrefix), '-', '')}ctl${uniqueString(resourceGroup().id)}', 24)
var queueUrl = 'https://${storageName}.queue.${environment().suffixes.storage}/${queueName}'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
  }
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource queue 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = {
  parent: queueService
  name: queueName
}

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: '${namePrefix}-azuresentinel'
  location: location
  // kind and parameterValueType are missing from Bicep's type index but are what the
  // Azure-Sentinel playbook templates use for a managed-identity Sentinel connection.
  #disable-next-line BCP187
  kind: 'V1'
  properties: {
    displayName: '${namePrefix} control playbooks'
    customParameterValues: {}
    #disable-next-line BCP037
    parameterValueType: 'Alternative' // managed identity, no stored credential
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
  }
}

var connections = {
  '$connections': {
    value: {
      azuresentinel: {
        connectionId: sentinelConnection.id
        connectionName: sentinelConnection.name
        id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
        connectionProperties: { authentication: { type: 'ManagedServiceIdentity' } }
      }
    }
  }
}

// Base64: the Put Message docs require markup in a message to be encoded, and an
// incident title may contain any character. gatehouse decodes either form.
var putMessage = {
  type: 'Http'
  runAfter: { Signal: ['Succeeded'] }
  inputs: {
    method: 'POST'
    uri: '${queueUrl}/messages'
    headers: { 'x-ms-version': '2021-12-02', 'Content-Type': 'application/xml' }
    body: '<QueueMessage><MessageText>@{base64(string(outputs(\'Signal\')))}</MessageText></QueueMessage>'
    authentication: { type: 'ManagedServiceIdentity', audience: 'https://storage.azure.com/' }
  }
}

var playbookDefs = [
  {
    name: '${namePrefix}-kill'
    trigger: {
      Microsoft_Sentinel_incident: {
        type: 'ApiConnectionWebhook'
        inputs: {
          body: { callback_url: '@{listCallbackUrl()}' }
          host: { connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' } }
          path: '/incident-creation'
        }
      }
    }
    message: loadJsonContent('playbook/kill-message.json')
  }
  {
    name: '${namePrefix}-lock'
    trigger: {
      Microsoft_Sentinel_alert: {
        type: 'ApiConnectionWebhook'
        inputs: {
          body: { callback_url: '@{listCallbackUrl()}' }
          host: { connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' } }
          path: '/subscribe'
        }
      }
    }
    message: loadJsonContent('playbook/lock-message.json')
  }
]

resource playbooks 'Microsoft.Logic/workflows@2019-05-01' = [
  for p in playbookDefs: {
    name: p.name
    location: location
    identity: { type: 'SystemAssigned' }
    properties: {
      state: 'Enabled'
      definition: {
        '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
        contentVersion: '1.0.0.0'
        parameters: { '$connections': { type: 'Object', defaultValue: {} } }
        triggers: p.trigger
        actions: {
          Signal: { type: 'Compose', runAfter: {}, inputs: p.message }
          Put_control_signal: putMessage
        }
      }
      parameters: connections
    }
  }
]

resource senderRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (p, i) in playbookDefs: {
    name: guid(queue.id, p.name, messageSender)
    scope: queue
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', messageSender)
      principalId: playbooks[i].identity.principalId
      principalType: 'ServicePrincipal'
    }
  }
]

resource listenerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(listenerPrincipalId)) {
  name: guid(queue.id, listenerPrincipalId, messageProcessor)
  scope: queue
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', messageProcessor)
    principalId: listenerPrincipalId
    principalType: listenerPrincipalType
  }
}

// Sentinel can only run playbooks in resource groups where its service principal holds
// Microsoft Sentinel Automation Contributor.
resource sentinelRunsPlaybooks 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(securityInsightsPrincipalId)) {
  name: guid(resourceGroup().id, securityInsightsPrincipalId, automationContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', automationContributor)
    principalId: securityInsightsPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource killRule 'Microsoft.SecurityInsights/automationRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'gatehouse-kill')
  properties: {
    displayName: 'gatehouse: kill switch on ${killSeverity} incidents'
    order: 100
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentRelatedAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: ruleIds
          }
        }
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentSeverity'
            operator: 'Equals'
            propertyValues: [killSeverity]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: { logicAppResourceId: playbooks[0].id, tenantId: tenant().tenantId }
      }
    ]
  }
  dependsOn: [sentinelRunsPlaybooks]
}

resource lockRule 'Microsoft.SecurityInsights/automationRules@2024-03-01' = if (lockOnAlerts) {
  scope: workspace
  name: guid(workspace.id, 'gatehouse-lock')
  properties: {
    displayName: 'gatehouse: lock the agent session on gatehouse alerts'
    order: 101
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Alerts'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'AlertAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: ruleIds
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: { logicAppResourceId: playbooks[1].id, tenantId: tenant().tenantId }
      }
    ]
  }
  dependsOn: [sentinelRunsPlaybooks]
}

@description('Set GATEHOUSE_CONTROL_QUEUE_URL to this (Entra auth), or to it plus a user delegation SAS.')
output controlQueueUrl string = queueUrl
output storageAccountName string = storage.name
