import type { InvitationType } from '../messages'

export enum OutOfBandRecordMetadataKeys {
  RecipientRouting = '_internal/recipientRouting',
  LegacyInvitation = '_internal/legacyInvitation',
}

export type OutOfBandRecordMetadata = {
  [OutOfBandRecordMetadataKeys.RecipientRouting]: {
    recipientKeyFingerprint: string
    routingKeyFingerprints: string[]
    endpoints: string[]
    mediatorId?: string
  }
  [OutOfBandRecordMetadataKeys.LegacyInvitation]: {
    /**
     * Indicates the type of the legacy invitation that was used for this out of band exchange.
     */
    legacyInvitationType?: Exclude<InvitationType, InvitationType.OutOfBand>
  }
}
