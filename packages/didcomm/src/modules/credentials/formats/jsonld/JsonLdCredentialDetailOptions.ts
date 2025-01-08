import { IsObject, IsOptional, IsString } from 'class-validator'

export interface JsonLdCredentialDetailCredentialStatusOptions {
  type: string
}

export class JsonLdCredentialDetailCredentialStatus {
  public constructor(options: JsonLdCredentialDetailCredentialStatusOptions) {
    if (options) {
      this.type = options.type
    }
  }
  @IsString()
  public type!: string
}

export interface JsonLdCredentialDetailOptionsOptions {
  proofPurpose: string
  created?: string
  domain?: string
  challenge?: string
  credentialStatus?: JsonLdCredentialDetailCredentialStatus
  proofType: string
}

export class JsonLdCredentialDetailOptions {
  public constructor(options: JsonLdCredentialDetailOptionsOptions) {
    if (options) {
      this.proofPurpose = options.proofPurpose
      this.created = options.created
      this.domain = options.domain
      this.challenge = options.challenge
      this.credentialStatus = options.credentialStatus
      this.proofType = options.proofType
    }
  }

  @IsString()
  public proofPurpose!: string

  @IsString()
  @IsOptional()
  public created?: string

  @IsString()
  @IsOptional()
  public domain?: string

  @IsString()
  @IsOptional()
  public challenge?: string

  @IsString()
  public proofType!: string

  @IsOptional()
  @IsObject()
  public credentialStatus?: JsonLdCredentialDetailCredentialStatus
}
