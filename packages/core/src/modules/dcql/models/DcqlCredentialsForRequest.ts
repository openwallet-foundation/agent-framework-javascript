import type { JsonObject } from '../../../types'
import type { MdocNameSpaces, MdocRecord } from '../../mdoc'
import type { SdJwtVcRecord } from '../../sd-jwt-vc'
import type { ClaimFormat, W3cCredentialRecord } from '../../vc'

/**
 * Mapping of credential query IDs to the selected credential record and the disclosed payload.
 */
export type DcqlCredentialsForRequest = Record<
  string,
  | {
      claimFormat: ClaimFormat.MsoMdoc
      credentialRecord: MdocRecord
      disclosedPayload: MdocNameSpaces
    }
  | {
      claimFormat: ClaimFormat.SdJwtVc
      credentialRecord: SdJwtVcRecord
      disclosedPayload: JsonObject
    }
  | {
      claimFormat: ClaimFormat.JwtVc | ClaimFormat.LdpVc
      credentialRecord: W3cCredentialRecord
      disclosedPayload: JsonObject
    }
>
