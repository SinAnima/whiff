// Storage for the harbour gauge readings.
targetScope = 'resourceGroup'

param location string = resourceGroup().location
var name = 'saltmeregauge'

resource store 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: name
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}

module alerts './alerts.bicep' = {
  name: 'alerts'
}

output storeId string = store.id
