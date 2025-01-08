export enum ConnectionMetadataKeys {
  UseDidKeysForProtocol = '_internal/useDidKeysForProtocol',
  DidRotate = '_internal/didRotate',
}

export type ConnectionMetadata = {
  [ConnectionMetadataKeys.UseDidKeysForProtocol]: {
    [protocolUri: string]: boolean
  }
  [ConnectionMetadataKeys.DidRotate]: {
    did: string
    threadId: string
    mediatorId?: string
  }
}
