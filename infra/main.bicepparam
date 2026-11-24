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
