export * from './DifPexCredentialsForRequest'
import type { Mdoc, MdocDeviceResponse } from '../../mdoc'
import type { SdJwtVc } from '../../sd-jwt-vc'
import type { W3cVerifiableCredential, W3cVerifiablePresentation } from '../../vc'
import type { PresentationDefinitionV1, PresentationDefinitionV2, PresentationSubmission } from '@sphereon/pex-models'

import { PresentationSubmissionLocation } from '@animo-id/pex'

// Re-export some types from sphereon library, but under more explicit names
export type DifPresentationExchangeDefinition = PresentationDefinitionV1 | PresentationDefinitionV2
export type DifPresentationExchangeDefinitionV1 = PresentationDefinitionV1
export type DifPresentationExchangeDefinitionV2 = PresentationDefinitionV2
export type DifPresentationExchangeSubmission = PresentationSubmission
export { PresentationSubmissionLocation as DifPresentationExchangeSubmissionLocation }

// TODO: we might want to move this to another place at some point
export type VerifiablePresentation = W3cVerifiablePresentation | SdJwtVc | MdocDeviceResponse
export type VerifiableCredential = W3cVerifiableCredential | SdJwtVc | Mdoc
