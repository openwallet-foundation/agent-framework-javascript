import type { Attachment } from '../../../../decorators/attachment/Attachment'
import type { LinkedAttachment } from '../../../../utils/LinkedAttachment'
import type { ParseRevocationRegistryDefinitionTemplate } from '../../../ledger/services'
import type { SignCredentialOptions } from '../../../vc/models/W3cCredentialServiceOptions'
import type { W3cCredential } from '../../../vc/models/credential/W3cCredential'
import type { AutoAcceptCredential } from '../../CredentialAutoAcceptType'
import type { ServiceRequestCredentialOptions } from '../../CredentialServiceOptions'
import type {
  CredentialPreviewAttribute,
  CredentialPreviewAttributeOptions,
} from '../../models/CredentialPreviewAttribute'
import type { V2CredentialPreview } from '../../protocol/v2/V2CredentialPreview'
import type { CredentialExchangeRecord } from '../../repository/CredentialExchangeRecord'
import type { CredPropose } from './CredPropose'
import type { CredDef } from 'indy-sdk'

import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { CredentialFormatType } from '../../CredentialsModuleOptions'

export type CredentialFormats =
  | FormatServiceOfferCredentialFormats
  | FormatServiceProposeCredentialFormats
  | FormatServiceRequestCredentialFormats
export interface IndyCredentialPreview {
  credentialDefinitionId?: string
  attributes?: CredentialPreviewAttribute[]
}

export interface IndyProposeCredentialFormat {
  attributes?: CredentialPreviewAttributeOptions[]
  linkedAttachments?: LinkedAttachment[]
  payload?: CredPropose
}
export interface IndyOfferCredentialFormat {
  credentialDefinitionId: string
  attributes: CredentialPreviewAttribute[]
  linkedAttachments?: LinkedAttachment[]
}
export interface IndyRequestCredentialFormat {
  credentialDefinitionId?: string
  attributes?: CredentialPreviewAttribute[]
}
export interface IndyIssueCredentialFormat {
  credentialDefinitionId?: string
  attributes?: CredentialPreviewAttribute[]
}

export class CredentialFormatSpec {
  public constructor(options: { attachId: string; format: string }) {
    if (options) {
      this.attachId = options.attachId
      this.format = options.format
    }
  }
  @Expose({ name: 'attach_id' })
  @IsString()
  public attachId!: string

  @IsString()
  public format!: string
}

export type FormatKeys = {
  [id: string]: CredentialFormatType
}

export interface FormatServiceCredentialAttachmentFormats {
  format: CredentialFormatSpec
  attachment: Attachment
}

export interface FormatServiceProposeAttachmentFormats extends FormatServiceCredentialAttachmentFormats {
  preview?: V2CredentialPreview
}

export interface FormatServiceOfferAttachmentFormats extends FormatServiceCredentialAttachmentFormats {
  preview?: V2CredentialPreview
}
export const FORMAT_KEYS: FormatKeys = {
  indy: CredentialFormatType.Indy,
  jsonld: CredentialFormatType.JsonLd,
}

export interface FormatServiceRequestCredentialOptions extends ServiceRequestCredentialOptions {
  indy?: {
    credentialDefinition?: {
      credDef: CredDef
    }
  }
  jsonld?: W3cCredential
}

export interface FormatServiceOfferCredentialFormats {
  indy?: IndyOfferCredentialFormat
  jsonld?: SignCredentialOptions
}

export interface FormatServiceProposeCredentialFormats {
  indy?: IndyProposeCredentialFormat
  jsonld?: SignCredentialOptions
}

export interface FormatServiceAcceptProposeCredentialFormats {
  indy?: {
    credentialDefinitionId?: string
    attributes: CredentialPreviewAttributeOptions[]
    linkedAttachments?: LinkedAttachment[]
  }
  jsonld?: SignCredentialOptions
}

export interface FormatServiceRequestCredentialFormats {
  indy?: IndyRequestCredentialFormat
  jsonld?: SignCredentialOptions
}

export interface FormatServiceIssueCredentialFormats {
  indy?: IndyIssueCredentialFormat
  jsonld?: SignCredentialOptions
}

export interface HandlerAutoAcceptOptions {
  credentialRecord: CredentialExchangeRecord
  autoAcceptType: AutoAcceptCredential
  messageAttributes?: CredentialPreviewAttribute[]
  proposalAttachment?: Attachment
  offerAttachment?: Attachment
  requestAttachment?: Attachment
  credentialAttachment?: Attachment
  credentialDefinitionId?: string
}

export interface RevocationRegistry {
  indy?: ParseRevocationRegistryDefinitionTemplate
  jsonld?: undefined
}
