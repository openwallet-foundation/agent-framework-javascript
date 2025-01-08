import { Expose, Type } from 'class-transformer'
import { ArrayNotEmpty, IsBoolean, IsEnum, IsOptional, IsString, ValidateNested } from 'class-validator'

import { JsonObject, JsonTransformer, W3cCredential } from '@credo-ts/core'

const SUPPORTED_W3C_VC_DATA_MODEL_VERSIONS = ['1.1', '2.0'] as const
export type W3C_VC_DATA_MODEL_VERSION = (typeof SUPPORTED_W3C_VC_DATA_MODEL_VERSIONS)[number]

export interface AnonCredsLinkSecretBindingMethodOptions {
  credentialDefinitionId: string
  nonce: string
  keyCorrectnessProof: Record<string, unknown>
}

// This binding method is intended to be used in combination with a credential containing an AnonCreds proof.
export class AnonCredsLinkSecretBindingMethod {
  public constructor(options: AnonCredsLinkSecretBindingMethodOptions) {
    if (options) {
      this.credentialDefinitionId = options.credentialDefinitionId
      this.nonce = options.nonce
      this.keyCorrectnessProof = options.keyCorrectnessProof
    }
  }

  @IsString()
  @Expose({ name: 'cred_def_id' })
  public credentialDefinitionId!: string

  @IsString()
  public nonce!: string

  @Expose({ name: 'key_correctness_proof' })
  public keyCorrectnessProof!: Record<string, unknown>
}

export interface DidCommSignedAttachmentBindingMethodOptions {
  algSupported: string[]
  didMethodsSupported: string[]
  nonce: string
}

export class DidCommSignedAttachmentBindingMethod {
  public constructor(options: DidCommSignedAttachmentBindingMethodOptions) {
    if (options) {
      this.algsSupported = options.algSupported
      this.didMethodsSupported = options.didMethodsSupported
      this.nonce = options.nonce
    }
  }

  @IsString({ each: true })
  @Expose({ name: 'algs_supported' })
  public algsSupported!: string[]

  @IsString({ each: true })
  @Expose({ name: 'did_methods_supported' })
  public didMethodsSupported!: string[]

  @IsString()
  public nonce!: string
}

export interface DataIntegrityBindingMethodsOptions {
  anonCredsLinkSecret?: AnonCredsLinkSecretBindingMethod
  didcommSignedAttachment?: DidCommSignedAttachmentBindingMethod
}

export class DataIntegrityBindingMethods {
  public constructor(options: DataIntegrityBindingMethodsOptions) {
    if (options) {
      this.anoncredsLinkSecret = options.anonCredsLinkSecret
      this.didcommSignedAttachment = options.didcommSignedAttachment
    }
  }

  @IsOptional()
  @ValidateNested()
  @Type(() => AnonCredsLinkSecretBindingMethod)
  @Expose({ name: 'anoncreds_link_secret' })
  public anoncredsLinkSecret?: AnonCredsLinkSecretBindingMethod

  @IsOptional()
  @ValidateNested()
  @Type(() => DidCommSignedAttachmentBindingMethod)
  @Expose({ name: 'didcomm_signed_attachment' })
  public didcommSignedAttachment?: DidCommSignedAttachmentBindingMethod
}

export interface DataIntegrityCredentialOfferOptions {
  dataModelVersionsSupported: W3C_VC_DATA_MODEL_VERSION[]
  bindingRequired?: boolean
  bindingMethod?: DataIntegrityBindingMethods
  credential: W3cCredential | JsonObject
}

export class DataIntegrityCredentialOffer {
  public constructor(options: DataIntegrityCredentialOfferOptions) {
    if (options) {
      this.credential =
        options.credential instanceof W3cCredential ? JsonTransformer.toJSON(options.credential) : options.credential
      this.bindingRequired = options.bindingRequired
      this.bindingMethod = options.bindingMethod
      this.dataModelVersionsSupported = options.dataModelVersionsSupported
    }
  }

  // List of strings indicating the supported VC Data Model versions.
  // The list MUST contain at least one value. The values MUST be a valid data model version. Current supported values include 1.1 and 2.0.
  @ArrayNotEmpty()
  @IsEnum(SUPPORTED_W3C_VC_DATA_MODEL_VERSIONS, { each: true })
  @Expose({ name: 'data_model_versions_supported' })
  public dataModelVersionsSupported!: W3C_VC_DATA_MODEL_VERSION[]

  // Boolean indicating whether the credential MUST be bound to the holder. If omitted, the credential is not required to be bound to the holder.
  // If set to true, the credential MUST be bound to the holder using at least one of the binding methods defined in binding_method.
  @IsOptional()
  @IsBoolean()
  @Expose({ name: 'binding_required' })
  public bindingRequired?: boolean

  // Required if binding_required is true.
  // Object containing key-value pairs of binding methods supported by the issuer to bind the credential to a holder.
  // If the value is omitted, this indicates the issuer does not support any binding methods for issuance of the credential.
  @IsOptional()
  @ValidateNested()
  @Type(() => DataIntegrityBindingMethods)
  @Expose({ name: 'binding_method' })
  public bindingMethod?: DataIntegrityBindingMethods

  // The credential should be compliant with the VC Data Model.
  // The credential MUST NOT contain any proofs.
  // Some properties MAY be omitted if they will only be available at time of issuance, such as issuanceDate, issuer, credentialSubject.id, credentialStatus, credentialStatus.id.
  // The credential MUST be conformant with one of the data model versions indicated in data_model_versions_supported.
  @Expose({ name: 'credential' })
  public credential!: JsonObject
}

export interface AnonCredsLinkSecretDataIntegrityBindingProof {
  cred_def_id: string
  entropy: string
  blinded_ms: Record<string, unknown>
  blinded_ms_correctness_proof: Record<string, unknown>
  nonce: string
}

export interface DidCommSignedAttachmentDataIntegrityBindingProof {
  // The id of the appended attachment included in the request message that contains the signed attachment.
  attachment_id: string
}

export interface DataIntegrityCredentialRequestBindingProof {
  anoncreds_link_secret?: AnonCredsLinkSecretDataIntegrityBindingProof
  didcomm_signed_attachment?: DidCommSignedAttachmentDataIntegrityBindingProof
}

export interface DataIntegrityCredentialRequest {
  // The data model version of the credential to be issued. The value MUST be a valid data model version and match one of the values from the data_model_versions_supported offer.
  data_model_version: W3C_VC_DATA_MODEL_VERSION
  // Required if binding_required is true in the offer.
  // Object containing key-value pairs of proofs for the binding to the holder.
  // The keys MUST match keys of the binding_method object from the offer.
  // See Binding Methods for a registry of default binding methods supported as part of this RFC.
  binding_proof?: DataIntegrityCredentialRequestBindingProof
}

export interface AnonCredsLinkSecretCredentialRequestOptions {
  linkSecretId?: string
}

export interface DidCommSignedAttachmentCredentialRequestOptions {
  kid: string
  alg?: string
}

export interface DataIntegrityCredential {
  credential: JsonObject
}
