// Example parameters. Copy, edit, and deploy with:
//   az deployment group create -g <resource-group> -f infra/main.bicep -p infra/main.bicepparam
using 'main.bicep'

param workspaceName = 'law-gatehouse'
param createWorkspace = true
param enableSentinel = true
param deployAnalyticsRules = true
// Object id of the identity gatehouse runs as (az ad signed-in-user show --query id -o tsv)
param publisherPrincipalId = ''
param publisherPrincipalType = 'User'
param retentionInDays = 90
// Control loop (D-055): queue + kill/lock playbooks + automation rules. Off by default.
param deployControlLoop = false
// The identity `gatehouse listen` runs as (often the same as publisherPrincipalId)
param listenerPrincipalId = ''
param listenerPrincipalType = 'User'
// az ad sp show --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 --query id -o tsv
param securityInsightsPrincipalId = ''
