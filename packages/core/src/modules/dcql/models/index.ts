export * from './DcqlCredentialsForRequest'
import type { VerifiablePresentation } from '../../dif-presentation-exchange'
import type { MdocRecord } from '../../mdoc'
import type { SdJwtVcRecord } from '../../sd-jwt-vc'
import type { W3cCredentialRecord } from '../../vc'
import type {
  DcqlQueryResult as _DcqlQueryResult,
  DcqlQuery as _DcqlQuery,
  DcqlCredential as _DcqlCredential,
  DcqlMdocCredential as _DcqlMdocCredential,
  DcqlW3cVcCredential as _DcqlW3cVcCredential,
  DcqlSdJwtVcCredential as _DcqlSdJwtVcCredential,
  DcqlPresentation as _DcqlPresentation,
  DcqlPresentationResult as _DcqlPresentationResult,
} from 'dcql'

export type DcqlQuery = _DcqlQuery.Input
export type DcqlCredential = _DcqlCredential.Model['Input']
export type DcqlMdocCredential = _DcqlMdocCredential.Model['Input']
export type DcqlSdJwtVcCredential = _DcqlSdJwtVcCredential.Model['Input']
export type DcqlW3cVcCredential = _DcqlW3cVcCredential.Model['Input']

export type DcqlMatchWithRecord =
  | (_DcqlQueryResult['credential_matches'][number] & {
      success: true
      record: MdocRecord | SdJwtVcRecord | W3cCredentialRecord
    })
  | (_DcqlQueryResult['credential_matches'][number] & {
      success: false
    })

export type DcqlQueryResult = Omit<_DcqlQueryResult.Input, 'credential_matches'> & {
  credential_matches: Record<string, DcqlMatchWithRecord>
}

export type DcqlEncodedPresentations = _DcqlPresentation.Input
export type DcqlPresentation = Record<string, VerifiablePresentation>

export type DcqlPresentationResult = _DcqlPresentationResult.Input
