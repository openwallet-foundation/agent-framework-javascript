import type { OpenId4VciCredentialOfferPayload } from '../../shared'
import type { RecordTags, TagsBase } from '@credo-ts/core'

import { CredoError, BaseRecord, utils, DateTransformer } from '@credo-ts/core'
import { Transform } from 'class-transformer'

import { OpenId4VcIssuanceSessionState } from '../OpenId4VcIssuanceSessionState'

export type OpenId4VcIssuanceSessionRecordTags = RecordTags<OpenId4VcIssuanceSessionRecord>

export type DefaultOpenId4VcIssuanceSessionRecordTags = {
  issuerId: string
  cNonce?: string
  preAuthorizedCode?: string
  state: OpenId4VcIssuanceSessionState
  credentialOfferUri: string
}

export interface OpenId4VcIssuanceSessionRecordProps {
  id?: string
  createdAt?: Date
  tags?: TagsBase

  issuerId: string

  cNonce?: string
  cNonceExpiresAt?: Date

  preAuthorizedCode?: string
  userPin?: string

  credentialOfferUri: string
  credentialOfferPayload: OpenId4VciCredentialOfferPayload

  issuanceMetadata?: Record<string, unknown>
  state: OpenId4VcIssuanceSessionState
  errorMessage?: string
}

export class OpenId4VcIssuanceSessionRecord extends BaseRecord<DefaultOpenId4VcIssuanceSessionRecordTags> {
  public static readonly type = 'OpenId4VcIssuanceSessionRecord'
  public readonly type = OpenId4VcIssuanceSessionRecord.type

  /**
   * The id of the issuer that this session is for.
   */
  public issuerId!: string

  /**
   * The state of the issuance session.
   */
  @Transform(({ value }) => {
    // CredentialIssued is an old state that is no longer used. It should be mapped to Error.
    if (value === 'CredentialIssued') {
      return OpenId4VcIssuanceSessionState.Error
    }

    return value
  })
  public state!: OpenId4VcIssuanceSessionState

  /**
   * The credentials that were issued during this session.
   */
  public issuedCredentials: string[] = []

  /**
   * cNonce that should be used in the credential request by the holder.
   */
  public cNonce?: string

  /**
   * The time at which the cNonce expires.
   */
  @DateTransformer()
  public cNonceExpiresAt?: Date

  /**
   * Pre authorized code used for the issuance session. Only used when a pre-authorized credential
   * offer is created.
   */
  public preAuthorizedCode?: string

  /**
   * Optional user pin that needs to be provided by the user in the access token request.
   */
  public userPin?: string

  /**
   * User-defined metadata that will be provided to the credential request to credential mapper
   * to allow to retrieve the needed credential input data. Can be the credential data itself,
   * or some other data that is needed to retrieve the credential data.
   */
  public issuanceMetadata?: Record<string, unknown>

  /**
   * The credential offer that was used to create the issuance session.
   */
  public credentialOfferPayload!: OpenId4VciCredentialOfferPayload

  /**
   * URI of the credential offer. This is the url that cn can be used to retrieve
   * the credential offer
   */
  public credentialOfferUri!: string

  /**
   * Optional error message of the error that occurred during the issuance session. Will be set when state is {@link OpenId4VcIssuanceSessionState.Error}
   */
  public errorMessage?: string

  public constructor(props: OpenId4VcIssuanceSessionRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this._tags = props.tags ?? {}

      this.issuerId = props.issuerId
      this.cNonce = props.cNonce
      this.cNonceExpiresAt = props.cNonceExpiresAt
      this.userPin = props.userPin
      this.preAuthorizedCode = props.preAuthorizedCode
      this.credentialOfferUri = props.credentialOfferUri
      this.credentialOfferPayload = props.credentialOfferPayload
      this.issuanceMetadata = props.issuanceMetadata
      this.state = props.state
      this.errorMessage = props.errorMessage
    }
  }

  public assertState(expectedStates: OpenId4VcIssuanceSessionState | OpenId4VcIssuanceSessionState[]) {
    if (!Array.isArray(expectedStates)) {
      expectedStates = [expectedStates]
    }

    if (!expectedStates.includes(this.state)) {
      throw new CredoError(
        `OpenId4VcIssuanceSessionRecord is in invalid state ${this.state}. Valid states are: ${expectedStates.join(
          ', '
        )}.`
      )
    }
  }

  public getTags() {
    return {
      ...this._tags,
      issuerId: this.issuerId,
      cNonce: this.cNonce,
      credentialOfferUri: this.credentialOfferUri,
      preAuthorizedCode: this.preAuthorizedCode,
      state: this.state,
    }
  }
}
