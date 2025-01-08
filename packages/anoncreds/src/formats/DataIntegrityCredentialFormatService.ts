import type { AnonCredsRevocationStatusList } from '../models'
import type { AnonCredsIssuerService, AnonCredsHolderService } from '../services'
import type { AnonCredsClaimRecord } from '../utils/credential'
import type { AnonCredsCredentialMetadata, AnonCredsCredentialRequestMetadata } from '../utils/metadata'
import type {
  AgentContext,
  JsonObject,
  JwaSignatureAlgorithm,
  JwsDetachedFormat,
  VerificationMethod,
  W3cCredentialRecord,
} from '@credo-ts/core'
import type {
  W3C_VC_DATA_MODEL_VERSION,
  DataIntegrityCredential,
  DataIntegrityCredentialRequest,
  AnonCredsLinkSecretBindingMethod,
  DidCommSignedAttachmentBindingMethod,
  DataIntegrityCredentialRequestBindingProof,
  AnonCredsLinkSecretDataIntegrityBindingProof,
  DidCommSignedAttachmentDataIntegrityBindingProof,
  DataIntegrityOfferCredentialFormat,
  DataIntegrityCredentialFormat,
  CredentialFormatService,
  CredentialFormatCreateProposalOptions,
  CredentialFormatCreateProposalReturn,
  CredentialFormatProcessOptions,
  CredentialFormatAcceptProposalOptions,
  CredentialFormatCreateOfferReturn,
  CredentialFormatCreateOfferOptions,
  CredentialFormatAcceptOfferOptions,
  CredentialFormatCreateReturn,
  CredentialFormatAcceptRequestOptions,
  CredentialFormatProcessCredentialOptions,
  CredentialFormatAutoRespondProposalOptions,
  CredentialFormatAutoRespondOfferOptions,
  CredentialFormatAutoRespondRequestOptions,
  CredentialFormatAutoRespondCredentialOptions,
  CredentialExchangeRecord,
  CredentialPreviewAttributeOptions,
} from '@credo-ts/didcomm'

import {
  JsonEncoder,
  JsonTransformer,
  W3cCredential,
  DidsApi,
  W3cCredentialService,
  W3cJsonLdVerifiableCredential,
  getJwkClassFromKeyType,
  JwsService,
  getKeyFromVerificationMethod,
  getJwkFromKey,
  ClaimFormat,
  JwtPayload,
  SignatureSuiteRegistry,
  CredoError,
  deepEquality,
  W3cCredentialSubject,
} from '@credo-ts/core'
import {
  ProblemReportError,
  CredentialFormatSpec,
  Attachment,
  CredentialProblemReportReason,
  AttachmentData,
  CredentialPreviewAttribute,
  DataIntegrityCredentialOffer,
} from '@credo-ts/didcomm'

import {
  AnonCredsCredentialDefinitionRepository,
  AnonCredsRevocationRegistryDefinitionPrivateRepository,
  AnonCredsRevocationRegistryState,
} from '../repository'
import { AnonCredsIssuerServiceSymbol, AnonCredsHolderServiceSymbol } from '../services'
import {
  dateToTimestamp,
  fetchCredentialDefinition,
  fetchRevocationRegistryDefinition,
  fetchRevocationStatusList,
  fetchSchema,
} from '../utils'
import {
  convertAttributesToCredentialValues,
  assertAttributesMatch as assertAttributesMatchSchema,
} from '../utils/credential'
import { AnonCredsCredentialMetadataKey, AnonCredsCredentialRequestMetadataKey } from '../utils/metadata'
import { getAnonCredsTagsFromRecord } from '../utils/w3cAnonCredsUtils'

const W3C_DATA_INTEGRITY_CREDENTIAL_OFFER = 'didcomm/w3c-di-vc-offer@v0.1'
const W3C_DATA_INTEGRITY_CREDENTIAL_REQUEST = 'didcomm/w3c-di-vc-request@v0.1'
const W3C_DATA_INTEGRITY_CREDENTIAL = 'didcomm/w3c-di-vc@v0.1'

export class DataIntegrityCredentialFormatService implements CredentialFormatService<DataIntegrityCredentialFormat> {
  /** formatKey is the key used when calling agent.credentials.xxx with credentialFormats.anoncreds */
  public readonly formatKey = 'dataIntegrity' as const

  /**
   * credentialRecordType is the type of record that stores the credential. It is stored in the credential
   * record binding in the credential exchange record.
   */
  public readonly credentialRecordType = 'w3c' as const

  /**
   * Create a {@link AttachmentFormats} object dependent on the message type.
   *
   * @param options The object containing all the options for the proposed credential
   * @returns object containing associated attachment, format and optionally the credential preview
   *
   */
  public async createProposal(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { credentialFormats, credentialRecord }: CredentialFormatCreateProposalOptions<DataIntegrityCredentialFormat>
  ): Promise<CredentialFormatCreateProposalReturn> {
    throw new CredoError('Not defined')
  }

  public async processProposal(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { attachment }: CredentialFormatProcessOptions
  ): Promise<void> {
    throw new CredoError('Not defined')
  }

  public async acceptProposal(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    input: CredentialFormatAcceptProposalOptions<DataIntegrityCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    throw new CredoError('Not defined')
  }

  /**
   * Create a credential attachment format for a credential request.
   *
   * @param options The object containing all the options for the credential offer
   * @returns object containing associated attachment, formats and offersAttach elements
   *
   */
  public async createOffer(
    agentContext: AgentContext,
    {
      credentialFormats,
      credentialRecord,
      attachmentId,
    }: CredentialFormatCreateOfferOptions<DataIntegrityCredentialFormat>
  ): Promise<CredentialFormatCreateOfferReturn> {
    const dataIntegrityFormat = credentialFormats.dataIntegrity
    if (!dataIntegrityFormat) throw new CredoError('Missing data integrity credential format data')

    const format = new CredentialFormatSpec({
      attachmentId: attachmentId,
      format: W3C_DATA_INTEGRITY_CREDENTIAL_OFFER,
    })

    const credential = dataIntegrityFormat.credential
    if ('proof' in credential) throw new CredoError('The offered credential MUST NOT contain any proofs.')

    const { dataIntegrityCredentialOffer, previewAttributes } = await this.createDataIntegrityCredentialOffer(
      agentContext,
      credentialRecord,
      dataIntegrityFormat
    )

    const attachment = this.getFormatData(JsonTransformer.toJSON(dataIntegrityCredentialOffer), format.attachmentId)
    return { format, attachment, previewAttributes }
  }

  private getCredentialVersion(credentialJson: JsonObject): W3C_VC_DATA_MODEL_VERSION {
    const context = credentialJson['@context']
    if (!context || !Array.isArray(context)) throw new CredoError('Invalid @context in credential offer')

    const isV1Credential = context.find((c) => c === 'https://www.w3.org/2018/credentials/v1')
    const isV2Credential = context.find((c) => c === 'https://www.w3.org/ns/credentials/v2')

    if (isV1Credential) return '1.1'
    else if (isV2Credential) throw new CredoError('Received w3c credential with unsupported version 2.0.')
    else throw new CredoError('Cannot determine credential version from @context')
  }

  public async processOffer(
    agentContext: AgentContext,
    { attachment, credentialRecord }: CredentialFormatProcessOptions
  ) {
    agentContext.config.logger.debug(
      `Processing data integrity credential offer for credential record ${credentialRecord.id}`
    )

    const dataIntegrityCredentialOffer = JsonTransformer.fromJSON(
      attachment.getDataAsJson(),
      DataIntegrityCredentialOffer
    )

    const credentialJson = dataIntegrityCredentialOffer.credential
    const credentialVersion = this.getCredentialVersion(credentialJson)

    const credentialToBeValidated = {
      ...credentialJson,
      issuer: credentialJson.issuer ?? 'https://example.com',
      ...(credentialVersion === '1.1'
        ? { issuanceDate: new Date().toISOString() }
        : { validFrom: new Date().toISOString() }),
    }

    JsonTransformer.fromJSON(credentialToBeValidated, W3cCredential)

    const missingBindingMethod =
      dataIntegrityCredentialOffer.bindingRequired &&
      !dataIntegrityCredentialOffer.bindingMethod?.anoncredsLinkSecret &&
      !dataIntegrityCredentialOffer.bindingMethod?.didcommSignedAttachment

    if (missingBindingMethod) {
      throw new ProblemReportError('Invalid credential offer. Missing binding method.', {
        problemCode: CredentialProblemReportReason.IssuanceAbandoned,
      })
    }
  }

  private async createSignedAttachment(
    agentContext: AgentContext,
    data: { nonce: string },
    options: { alg?: string; kid: string },
    issuerSupportedAlgs: string[]
  ) {
    const { alg, kid } = options

    if (!kid.startsWith('did:')) {
      throw new CredoError(`kid '${kid}' is not a DID. Only dids are supported for kid`)
    } else if (!kid.includes('#')) {
      throw new CredoError(
        `kid '${kid}' does not contain a fragment. kid MUST point to a specific key in the did document.`
      )
    }

    const didsApi = agentContext.dependencyManager.resolve(DidsApi)
    const didDocument = await didsApi.resolveDidDocument(kid)
    const verificationMethod = didDocument.dereferenceKey(kid)
    const key = getKeyFromVerificationMethod(verificationMethod)
    const jwk = getJwkFromKey(key)

    if (alg && !jwk.supportsSignatureAlgorithm(alg)) {
      throw new CredoError(`key type '${jwk.keyType}', does not support the JWS signature alg '${alg}'`)
    }

    const signingAlg = issuerSupportedAlgs.find(
      (supportedAlg) => jwk.supportsSignatureAlgorithm(supportedAlg) && (alg === undefined || alg === supportedAlg)
    )
    if (!signingAlg) throw new CredoError('No signing algorithm supported by the issuer found')

    const jwsService = agentContext.dependencyManager.resolve(JwsService)
    const jws = await jwsService.createJws(agentContext, {
      key,
      header: {},
      payload: new JwtPayload({ additionalClaims: { nonce: data.nonce } }),
      protectedHeaderOptions: { alg: signingAlg, kid },
    })

    const signedAttach = new Attachment({
      mimeType: 'application/json',
      data: new AttachmentData({ base64: jws.payload }),
    })

    signedAttach.addJws(jws)

    return signedAttach
  }

  private async getSignedAttachmentPayload(agentContext: AgentContext, signedAttachment: Attachment) {
    const jws = signedAttachment.data.jws as JwsDetachedFormat
    if (!jws) throw new CredoError('Missing jws in signed attachment')
    if (!jws.protected) throw new CredoError('Missing protected header in signed attachment')
    if (!signedAttachment.data.base64) throw new CredoError('Missing payload in signed attachment')

    const jwsService = agentContext.dependencyManager.resolve(JwsService)
    const { isValid } = await jwsService.verifyJws(agentContext, {
      jws: {
        header: jws.header,
        protected: jws.protected,
        signature: jws.signature,
        payload: signedAttachment.data.base64,
      },
      jwkResolver: async ({ protectedHeader: { kid } }) => {
        if (!kid || typeof kid !== 'string') throw new CredoError('Missing kid in protected header.')
        if (!kid.startsWith('did:')) throw new CredoError('Only did is supported for kid identifier')

        const didsApi = agentContext.dependencyManager.resolve(DidsApi)
        const didDocument = await didsApi.resolveDidDocument(kid)
        const verificationMethod = didDocument.dereferenceKey(kid)
        const key = getKeyFromVerificationMethod(verificationMethod)
        return getJwkFromKey(key)
      },
    })

    if (!isValid) throw new CredoError('Failed to validate signature of signed attachment')
    const payload = JsonEncoder.fromBase64(signedAttachment.data.base64) as { nonce: string }
    if (!payload.nonce || typeof payload.nonce !== 'string') {
      throw new CredoError('Invalid payload in signed attachment')
    }

    return payload
  }

  public async acceptOffer(
    agentContext: AgentContext,
    {
      credentialRecord,
      attachmentId,
      offerAttachment,
      credentialFormats,
    }: CredentialFormatAcceptOfferOptions<DataIntegrityCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    const dataIntegrityFormat = credentialFormats?.dataIntegrity

    const credentialOffer = JsonTransformer.fromJSON(offerAttachment.getDataAsJson(), DataIntegrityCredentialOffer)

    let anonCredsLinkSecretDataIntegrityBindingProof: AnonCredsLinkSecretDataIntegrityBindingProof | undefined =
      undefined
    const autoAcceptOfferWithAnonCredsLinkSecretMethod =
      credentialOffer.bindingRequired &&
      !dataIntegrityFormat?.didCommSignedAttachment &&
      credentialOffer.bindingMethod?.anoncredsLinkSecret

    if (dataIntegrityFormat?.anonCredsLinkSecret || autoAcceptOfferWithAnonCredsLinkSecretMethod) {
      if (!credentialOffer.bindingMethod?.anoncredsLinkSecret) {
        throw new CredoError('Cannot request credential with a binding method that was not offered.')
      }

      const anonCredsHolderService =
        agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

      const credentialDefinitionId = credentialOffer.bindingMethod.anoncredsLinkSecret.credentialDefinitionId
      const credentialDefinitionReturn = await fetchCredentialDefinition(agentContext, credentialDefinitionId)

      const {
        credentialRequest: anonCredsCredentialRequest,
        credentialRequestMetadata: anonCredsCredentialRequestMetadata,
      } = await anonCredsHolderService.createCredentialRequest(agentContext, {
        credentialOffer: {
          schema_id: credentialDefinitionReturn.credentialDefinition.schemaId,
          cred_def_id: credentialOffer.bindingMethod.anoncredsLinkSecret.credentialDefinitionId,
          key_correctness_proof: credentialOffer.bindingMethod.anoncredsLinkSecret.keyCorrectnessProof,
          nonce: credentialOffer.bindingMethod.anoncredsLinkSecret.nonce,
        },
        credentialDefinition: credentialDefinitionReturn.credentialDefinition,
        linkSecretId: dataIntegrityFormat?.anonCredsLinkSecret?.linkSecretId,
      })

      if (!anonCredsCredentialRequest.entropy) throw new CredoError('Missing entropy for anonCredsCredentialRequest')
      anonCredsLinkSecretDataIntegrityBindingProof =
        anonCredsCredentialRequest as AnonCredsLinkSecretDataIntegrityBindingProof

      credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
        credentialDefinitionId: credentialOffer.bindingMethod.anoncredsLinkSecret.credentialDefinitionId,
        schemaId: credentialDefinitionReturn.credentialDefinition.schemaId,
      })
      credentialRecord.metadata.set<AnonCredsCredentialRequestMetadata>(
        AnonCredsCredentialRequestMetadataKey,
        anonCredsCredentialRequestMetadata
      )
    }

    let didCommSignedAttachmentBindingProof: DidCommSignedAttachmentDataIntegrityBindingProof | undefined = undefined
    let didCommSignedAttachment: Attachment | undefined = undefined
    if (dataIntegrityFormat?.didCommSignedAttachment) {
      if (!credentialOffer.bindingMethod?.didcommSignedAttachment) {
        throw new CredoError('Cannot request credential with a binding method that was not offered.')
      }

      didCommSignedAttachment = await this.createSignedAttachment(
        agentContext,
        { nonce: credentialOffer.bindingMethod.didcommSignedAttachment.nonce },
        dataIntegrityFormat.didCommSignedAttachment,
        credentialOffer.bindingMethod.didcommSignedAttachment.algsSupported
      )

      didCommSignedAttachmentBindingProof = { attachment_id: didCommSignedAttachment.id }
    }

    const bindingProof: DataIntegrityCredentialRequestBindingProof | undefined =
      !anonCredsLinkSecretDataIntegrityBindingProof && !didCommSignedAttachmentBindingProof
        ? undefined
        : {
            anoncreds_link_secret: anonCredsLinkSecretDataIntegrityBindingProof,
            didcomm_signed_attachment: didCommSignedAttachmentBindingProof,
          }

    if (credentialOffer.bindingRequired && !bindingProof) throw new CredoError('Missing required binding proof')

    const dataModelVersion = dataIntegrityFormat?.dataModelVersion ?? credentialOffer.dataModelVersionsSupported[0]
    if (!credentialOffer.dataModelVersionsSupported.includes(dataModelVersion)) {
      throw new CredoError('Cannot request credential with a data model version that was not offered.')
    }

    const credentialRequest: DataIntegrityCredentialRequest = {
      data_model_version: dataModelVersion,
      binding_proof: bindingProof,
    }

    const format = new CredentialFormatSpec({
      attachmentId,
      format: W3C_DATA_INTEGRITY_CREDENTIAL_REQUEST,
    })

    const attachment = this.getFormatData(credentialRequest, format.attachmentId)
    return { format, attachment, appendAttachments: didCommSignedAttachment ? [didCommSignedAttachment] : undefined }
  }

  /**
   * Starting from a request is not supported for anoncreds credentials, this method only throws an error.
   */
  public async createRequest(): Promise<CredentialFormatCreateReturn> {
    throw new CredoError('Starting from a request is not supported for w3c credentials')
  }

  /**
   * We don't have any models to validate an anoncreds request object, for now this method does nothing
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async processRequest(agentContext: AgentContext, options: CredentialFormatProcessOptions): Promise<void> {
    // not needed for dataIntegrity
  }

  private async createCredentialWithAnonCredsDataIntegrityProof(
    agentContext: AgentContext,
    input: {
      credentialRecord: CredentialExchangeRecord
      anonCredsLinkSecretBindingMethod: AnonCredsLinkSecretBindingMethod
      anonCredsLinkSecretBindingProof: AnonCredsLinkSecretDataIntegrityBindingProof
      linkSecretMetadata: AnonCredsCredentialMetadata
      credentialSubjectId?: string
    }
  ): Promise<W3cJsonLdVerifiableCredential> {
    const {
      credentialRecord,
      anonCredsLinkSecretBindingMethod,
      anonCredsLinkSecretBindingProof,
      linkSecretMetadata,
      credentialSubjectId,
    } = input

    const credentialAttributes = credentialRecord.credentialAttributes
    if (!credentialAttributes) {
      throw new CredoError(
        `Missing required credential attribute values on credential record with id ${credentialRecord.id}`
      )
    }

    const credentialSubjectIdAttribute = credentialAttributes.find((ca) => ca.name === 'id')
    if (
      credentialSubjectId &&
      credentialSubjectIdAttribute &&
      credentialSubjectIdAttribute.value !== credentialSubjectId
    ) {
      throw new CredoError('Invalid credential subject id.')
    } else if (!credentialSubjectIdAttribute && credentialSubjectId) {
      credentialAttributes.push(new CredentialPreviewAttribute({ name: 'id', value: credentialSubjectId }))
    }

    const anonCredsIssuerService =
      agentContext.dependencyManager.resolve<AnonCredsIssuerService>(AnonCredsIssuerServiceSymbol)

    const credentialDefinition = (
      await agentContext.dependencyManager
        .resolve(AnonCredsCredentialDefinitionRepository)
        .getByCredentialDefinitionId(agentContext, linkSecretMetadata.credentialDefinitionId as string)
    ).credentialDefinition.value

    // We check locally for credential definition info. If it supports revocation, we need to search locally for
    // an active revocation registry
    let revocationRegistryDefinitionId: string | undefined = undefined
    let revocationRegistryIndex: number | undefined = undefined
    let revocationStatusList: AnonCredsRevocationStatusList | undefined = undefined

    if (credentialDefinition.revocation) {
      const { credentialRevocationId, revocationRegistryId } = linkSecretMetadata

      if (!credentialRevocationId || !revocationRegistryId) {
        throw new CredoError(
          'Revocation registry definition id and revocation index are mandatory to issue AnonCreds revocable credentials'
        )
      }

      revocationRegistryDefinitionId = revocationRegistryId
      revocationRegistryIndex = Number(credentialRevocationId)

      const revocationRegistryDefinitionPrivateRecord = await agentContext.dependencyManager
        .resolve(AnonCredsRevocationRegistryDefinitionPrivateRepository)
        .getByRevocationRegistryDefinitionId(agentContext, revocationRegistryDefinitionId)

      if (revocationRegistryDefinitionPrivateRecord.state !== AnonCredsRevocationRegistryState.Active) {
        throw new CredoError(
          `Revocation registry ${revocationRegistryDefinitionId} is in ${revocationRegistryDefinitionPrivateRecord.state} state`
        )
      }

      const revocationStatusListResult = await fetchRevocationStatusList(
        agentContext,
        revocationRegistryDefinitionId,
        dateToTimestamp(new Date())
      )

      revocationStatusList = revocationStatusListResult.revocationStatusList
    }

    const { credential } = await anonCredsIssuerService.createCredential(agentContext, {
      credentialOffer: {
        schema_id: linkSecretMetadata.schemaId as string,
        cred_def_id: anonCredsLinkSecretBindingMethod.credentialDefinitionId,
        key_correctness_proof: anonCredsLinkSecretBindingMethod.keyCorrectnessProof,
        nonce: anonCredsLinkSecretBindingMethod.nonce,
      },
      credentialRequest: anonCredsLinkSecretBindingProof,
      credentialValues: convertAttributesToCredentialValues(credentialAttributes),
      revocationRegistryDefinitionId,
      revocationRegistryIndex,
      revocationStatusList,
    })

    const { credentialDefinition: anoncredsCredentialDefinition } = await fetchCredentialDefinition(
      agentContext,
      credential.cred_def_id
    )

    const anonCredsHolderService =
      agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)
    return await anonCredsHolderService.legacyToW3cCredential(agentContext, {
      credential,
      issuerId: anoncredsCredentialDefinition.issuerId,
    })
  }

  private async getSignatureMetadata(
    agentContext: AgentContext,
    offeredCredential: W3cCredential,
    issuerVerificationMethod?: string
  ) {
    const didsApi = agentContext.dependencyManager.resolve(DidsApi)
    const didDocument = await didsApi.resolveDidDocument(offeredCredential.issuerId)

    let verificationMethod: VerificationMethod
    if (issuerVerificationMethod) {
      verificationMethod = didDocument.dereferenceKey(issuerVerificationMethod, ['authentication', 'assertionMethod'])
    } else {
      const vms = didDocument.authentication ?? didDocument.assertionMethod ?? didDocument.verificationMethod
      if (!vms || vms.length === 0) {
        throw new CredoError('Missing authenticationMethod, assertionMethod, and verificationMethods in did document')
      }

      if (typeof vms[0] === 'string') {
        verificationMethod = didDocument.dereferenceVerificationMethod(vms[0])
      } else {
        verificationMethod = vms[0]
      }
    }

    const signatureSuiteRegistry = agentContext.dependencyManager.resolve(SignatureSuiteRegistry)
    const signatureSuite = signatureSuiteRegistry.getByVerificationMethodType(verificationMethod.type)
    if (!signatureSuite) {
      throw new CredoError(`Could not find signature suite for verification method type ${verificationMethod.type}`)
    }

    return { verificationMethod, signatureSuite, offeredCredential }
  }

  private async assertAndSetCredentialSubjectId(credential: W3cCredential, credentialSubjectId: string | undefined) {
    if (!credentialSubjectId) return credential

    if (Array.isArray(credential.credentialSubject)) {
      throw new CredoError('Invalid credential subject relation. Cannot determine the subject to be updated.')
    }

    const subjectId = credential.credentialSubject.id
    if (subjectId && credentialSubjectId !== subjectId) {
      throw new CredoError('Invalid credential subject id.')
    }

    if (!subjectId) credential.credentialSubject.id = credentialSubjectId

    return credential
  }

  private async signCredential(
    agentContext: AgentContext,
    credential: W3cCredential | W3cJsonLdVerifiableCredential,
    issuerVerificationMethod?: string
  ) {
    const { signatureSuite, verificationMethod } = await this.getSignatureMetadata(
      agentContext,
      credential,
      issuerVerificationMethod
    )
    const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)

    let credentialToBeSigned = credential
    if (credential instanceof W3cJsonLdVerifiableCredential) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { proof, ..._credentialToBeSigned } = credential
      credentialToBeSigned = _credentialToBeSigned as W3cCredential
    }

    const w3cJsonLdVerifiableCredential = (await w3cCredentialService.signCredential(agentContext, {
      format: ClaimFormat.LdpVc,
      credential: credentialToBeSigned as W3cCredential,
      proofType: signatureSuite.proofType,
      verificationMethod: verificationMethod.id,
    })) as W3cJsonLdVerifiableCredential

    if (Array.isArray(w3cJsonLdVerifiableCredential.proof)) {
      throw new CredoError('A newly signed credential can not have multiple proofs')
    }

    if (credential instanceof W3cJsonLdVerifiableCredential) {
      const combinedProofs = Array.isArray(credential.proof) ? credential.proof : [credential.proof]
      combinedProofs.push(w3cJsonLdVerifiableCredential.proof)
      w3cJsonLdVerifiableCredential.proof = combinedProofs
    }
    return w3cJsonLdVerifiableCredential
  }

  public async acceptRequest(
    agentContext: AgentContext,
    {
      credentialFormats,
      credentialRecord,
      attachmentId,
      offerAttachment,
      requestAttachment,
      requestAppendAttachments,
    }: CredentialFormatAcceptRequestOptions<DataIntegrityCredentialFormat>
  ): Promise<CredentialFormatCreateReturn> {
    const dataIntegrityFormat = credentialFormats?.dataIntegrity

    const credentialOffer = JsonTransformer.fromJSON(offerAttachment?.getDataAsJson(), DataIntegrityCredentialOffer)

    const assertedCredential = await this.assertAndSetCredentialSubjectId(
      JsonTransformer.fromJSON(credentialOffer.credential, W3cCredential),
      dataIntegrityFormat?.credentialSubjectId
    )

    const credentialRequest = requestAttachment.getDataAsJson<DataIntegrityCredentialRequest>()
    if (!credentialRequest) throw new CredoError('Missing data integrity credential request in createCredential')

    let signedCredential: W3cJsonLdVerifiableCredential | undefined
    if (credentialRequest.binding_proof?.anoncreds_link_secret) {
      if (!credentialOffer.bindingMethod?.anoncredsLinkSecret) {
        throw new CredoError('Cannot issue credential with a binding method that was not offered')
      }

      const linkSecretMetadata =
        credentialRecord.metadata.get<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey)
      if (!linkSecretMetadata) throw new CredoError('Missing anoncreds link secret metadata')

      signedCredential = await this.createCredentialWithAnonCredsDataIntegrityProof(agentContext, {
        credentialRecord,
        anonCredsLinkSecretBindingMethod: credentialOffer.bindingMethod.anoncredsLinkSecret,
        linkSecretMetadata,
        anonCredsLinkSecretBindingProof: credentialRequest.binding_proof.anoncreds_link_secret,
        credentialSubjectId: dataIntegrityFormat?.credentialSubjectId,
      })
    }

    if (credentialRequest.binding_proof?.didcomm_signed_attachment) {
      if (!credentialOffer.bindingMethod?.didcommSignedAttachment) {
        throw new CredoError('Cannot issue credential with a binding method that was not offered')
      }

      const bindingProofAttachment = requestAppendAttachments?.find(
        (attachments) => attachments.id === credentialRequest.binding_proof?.didcomm_signed_attachment?.attachment_id
      )
      if (!bindingProofAttachment) throw new CredoError('Missing binding proof attachment')

      const { nonce } = await this.getSignedAttachmentPayload(agentContext, bindingProofAttachment)
      if (nonce !== credentialOffer.bindingMethod.didcommSignedAttachment.nonce) {
        throw new CredoError('Invalid nonce in signed attachment')
      }

      signedCredential = await this.signCredential(
        agentContext,
        signedCredential ?? assertedCredential,
        dataIntegrityFormat?.issuerVerificationMethod
      )
    }

    if (
      !credentialRequest.binding_proof?.anoncreds_link_secret &&
      !credentialRequest.binding_proof?.didcomm_signed_attachment
    ) {
      signedCredential = await this.signCredential(agentContext, assertedCredential)
    }

    const format = new CredentialFormatSpec({
      attachmentId,
      format: W3C_DATA_INTEGRITY_CREDENTIAL,
    })

    const attachment = this.getFormatData({ credential: JsonTransformer.toJSON(signedCredential) }, format.attachmentId)
    return { format, attachment }
  }

  private async storeAnonCredsCredential(
    agentContext: AgentContext,
    credentialJson: JsonObject,
    credentialRecord: CredentialExchangeRecord,
    linkSecretRequestMetadata: AnonCredsCredentialRequestMetadata
  ) {
    if (!credentialRecord.credentialAttributes) {
      throw new CredoError('Missing credential attributes on credential record. Unable to check credential attributes')
    }

    const anonCredsHolderService =
      agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    const legacyAnonCredsCredential = await anonCredsHolderService.w3cToLegacyCredential(agentContext, {
      credential: JsonTransformer.fromJSON(credentialJson, W3cJsonLdVerifiableCredential),
    })

    const {
      schema_id: schemaId,
      cred_def_id: credentialDefinitionId,
      rev_reg_id: revocationRegistryId,
    } = legacyAnonCredsCredential

    const schemaReturn = await fetchSchema(agentContext, schemaId)
    const credentialDefinitionReturn = await fetchCredentialDefinition(agentContext, credentialDefinitionId)
    const revocationRegistryDefinitionReturn = revocationRegistryId
      ? await fetchRevocationRegistryDefinition(agentContext, revocationRegistryId)
      : undefined

    // This is required to process the credential
    const w3cJsonLdVerifiableCredential = await anonCredsHolderService.legacyToW3cCredential(agentContext, {
      credential: legacyAnonCredsCredential,
      issuerId: credentialJson.issuer as string,
      processOptions: {
        credentialRequestMetadata: linkSecretRequestMetadata,
        credentialDefinition: credentialDefinitionReturn.credentialDefinition,
        revocationRegistryDefinition: revocationRegistryDefinitionReturn?.revocationRegistryDefinition,
      },
    })

    const w3cCredentialRecordId = await anonCredsHolderService.storeCredential(agentContext, {
      credential: w3cJsonLdVerifiableCredential,
      schema: schemaReturn.schema,
      credentialDefinitionId,
      credentialDefinition: credentialDefinitionReturn.credentialDefinition,
      credentialRequestMetadata: linkSecretRequestMetadata,
      revocationRegistry: revocationRegistryDefinitionReturn
        ? {
            id: revocationRegistryId as string,
            definition: revocationRegistryDefinitionReturn?.revocationRegistryDefinition,
          }
        : undefined,
    })

    const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
    const w3cCredentialRecord = await w3cCredentialService.getCredentialRecordById(agentContext, w3cCredentialRecordId)

    // If the credential is revocable, store the revocation identifiers in the credential record
    if (revocationRegistryId) {
      const linkSecretMetadata =
        credentialRecord.metadata.get<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey)
      if (!linkSecretMetadata) throw new CredoError('Missing link secret metadata')

      const anonCredsTags = await getAnonCredsTagsFromRecord(w3cCredentialRecord)
      if (!anonCredsTags) throw new CredoError('Missing anoncreds tags on credential record.')

      linkSecretMetadata.revocationRegistryId = revocationRegistryDefinitionReturn?.revocationRegistryDefinitionId
      linkSecretMetadata.credentialRevocationId = anonCredsTags.anonCredsCredentialRevocationId?.toString()
      credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, linkSecretMetadata)
    }

    return w3cCredentialRecord
  }

  /**
   * Processes an incoming credential - retrieve metadata, retrieve payload and store it in wallet
   * @param options the issue credential message wrapped inside this object
   * @param credentialRecord the credential exchange record for this credential
   */
  public async processCredential(
    agentContext: AgentContext,
    { credentialRecord, attachment, requestAttachment, offerAttachment }: CredentialFormatProcessCredentialOptions
  ): Promise<void> {
    const credentialOffer = JsonTransformer.fromJSON(offerAttachment.getDataAsJson(), DataIntegrityCredentialOffer)
    const offeredCredentialJson = credentialOffer.credential

    const credentialRequest = requestAttachment.getDataAsJson<DataIntegrityCredentialRequest>()
    if (!credentialRequest) throw new CredoError('Missing data integrity credential request in createCredential')

    if (!credentialRecord.credentialAttributes) {
      throw new CredoError('Missing credential attributes on credential record.')
    }

    const { credential: credentialJson } = attachment.getDataAsJson<DataIntegrityCredential>()

    if (Array.isArray(offeredCredentialJson.credentialSubject)) {
      throw new CredoError('Invalid credential subject. Multiple credential subjects are not yet supported.')
    }

    const credentialSubjectMatches = Object.entries(offeredCredentialJson.credentialSubject as JsonObject).every(
      ([key, offeredValue]) => {
        const receivedValue = (credentialJson.credentialSubject as JsonObject)[key]
        if (!offeredValue || !receivedValue) return false

        if (typeof offeredValue === 'number' || typeof receivedValue === 'number') {
          return offeredValue.toString() === receivedValue.toString()
        }

        return deepEquality(offeredValue, receivedValue)
      }
    )

    if (!credentialSubjectMatches) {
      throw new CredoError(
        'Received invalid credential. Received credential subject does not match the offered credential subject.'
      )
    }

    const credentialVersion = this.getCredentialVersion(credentialJson)
    const expectedReceivedCredential = {
      ...offeredCredentialJson,
      '@context': credentialJson['@context'],
      issuer: offeredCredentialJson.issuer ?? credentialJson.issuer,
      credentialSubject: credentialJson.credentialSubject,
      ...(credentialVersion === '1.1' && { issuanceDate: credentialJson.issuanceDate }),
      ...(credentialVersion === '2.0' && { validFrom: credentialJson.validFrom }),
      ...(offeredCredentialJson.credentialStatus && { credentialStatus: credentialJson.credentialStatus }),
      proof: credentialJson.proof,
    }

    if (!deepEquality(credentialJson, expectedReceivedCredential)) {
      throw new CredoError('Received invalid credential. Received credential does not match the offered credential')
    }

    let w3cCredentialRecord: W3cCredentialRecord
    if (credentialRequest.binding_proof?.anoncreds_link_secret) {
      const linkSecretRequestMetadata = credentialRecord.metadata.get<AnonCredsCredentialRequestMetadata>(
        AnonCredsCredentialRequestMetadataKey
      )
      if (!linkSecretRequestMetadata) {
        throw new CredoError('Missing link secret request metadata')
      }

      const integrityProtectedFields = ['@context', 'issuer', 'type', 'credentialSubject', 'validFrom', 'issuanceDate']
      if (
        Object.keys(offeredCredentialJson).some((key) => !integrityProtectedFields.includes(key) && key !== 'proof')
      ) {
        throw new CredoError('Credential offer contains non anoncreds integrity protected fields.')
      }

      if (!Array.isArray(offeredCredentialJson.type) || offeredCredentialJson?.type.length !== 1) {
        throw new CredoError(`Invalid credential type. Only single credential type 'VerifiableCredential' is supported`)
      }

      w3cCredentialRecord = await this.storeAnonCredsCredential(
        agentContext,
        credentialJson,
        credentialRecord,
        linkSecretRequestMetadata
      )

      await this.assertCredentialAttributesMatchSchemaAttributes(
        agentContext,
        w3cCredentialRecord.credential,
        getAnonCredsTagsFromRecord(w3cCredentialRecord)?.anonCredsSchemaId as string,
        true
      )
    } else {
      const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
      const w3cJsonLdVerifiableCredential = JsonTransformer.fromJSON(credentialJson, W3cJsonLdVerifiableCredential)
      w3cCredentialRecord = await w3cCredentialService.storeCredential(agentContext, {
        credential: w3cJsonLdVerifiableCredential,
      })
    }

    credentialRecord.credentials.push({
      credentialRecordType: this.credentialRecordType,
      credentialRecordId: w3cCredentialRecord.id,
    })
  }

  public supportsFormat(format: string): boolean {
    const supportedFormats = [
      W3C_DATA_INTEGRITY_CREDENTIAL_REQUEST,
      W3C_DATA_INTEGRITY_CREDENTIAL_OFFER,
      W3C_DATA_INTEGRITY_CREDENTIAL,
    ]

    return supportedFormats.includes(format)
  }

  /**
   * Gets the attachment object for a given attachmentId. We need to get out the correct attachmentId for
   * anoncreds and then find the corresponding attachment (if there is one)
   * @param formats the formats object containing the attachmentId
   * @param messageAttachments the attachments containing the payload
   * @returns The Attachment if found or undefined
   *
   */
  public getAttachment(formats: CredentialFormatSpec[], messageAttachments: Attachment[]): Attachment | undefined {
    const supportedAttachmentIds = formats.filter((f) => this.supportsFormat(f.format)).map((f) => f.attachmentId)
    const supportedAttachment = messageAttachments.find((attachment) => supportedAttachmentIds.includes(attachment.id))

    return supportedAttachment
  }

  public async deleteCredentialById(agentContext: AgentContext, credentialRecordId: string): Promise<void> {
    const anonCredsHolderService =
      agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    await anonCredsHolderService.deleteCredential(agentContext, credentialRecordId)
  }

  public async shouldAutoRespondToProposal(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { offerAttachment, proposalAttachment }: CredentialFormatAutoRespondProposalOptions
  ) {
    throw new CredoError('Not implemented')
    return false
  }

  public async shouldAutoRespondToOffer(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { offerAttachment }: CredentialFormatAutoRespondOfferOptions
  ) {
    const credentialOffer = JsonTransformer.fromJSON(offerAttachment.getDataAsJson(), DataIntegrityCredentialOffer)
    if (!credentialOffer.bindingRequired) return true
    return false
  }

  public async shouldAutoRespondToRequest(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    { offerAttachment, requestAttachment }: CredentialFormatAutoRespondRequestOptions
  ) {
    const credentialOffer = JsonTransformer.fromJSON(offerAttachment?.getDataAsJson(), DataIntegrityCredentialOffer)
    const credentialRequest = requestAttachment.getDataAsJson<DataIntegrityCredentialRequest>()

    if (
      !credentialOffer.bindingRequired &&
      !credentialRequest.binding_proof?.anoncreds_link_secret &&
      !credentialRequest.binding_proof?.didcomm_signed_attachment
    ) {
      return true
    }

    if (
      credentialOffer.bindingRequired &&
      !credentialRequest.binding_proof?.anoncreds_link_secret &&
      !credentialRequest.binding_proof?.didcomm_signed_attachment
    ) {
      return false
    }

    // cannot auto response credential subject id must be set manually
    if (credentialRequest.binding_proof?.didcomm_signed_attachment) {
      try {
        const subjectJson = credentialOffer.credential.credentialSubject
        const credentialSubject = JsonTransformer.fromJSON(subjectJson, W3cCredentialSubject)
        if (credentialSubject.id === undefined) return false
      } catch (e) {
        return false
      }
    }

    const validLinkSecretRequest =
      !credentialRequest.binding_proof?.anoncreds_link_secret ||
      (credentialRequest.binding_proof?.anoncreds_link_secret && credentialOffer.bindingMethod?.anoncredsLinkSecret)

    const validDidCommSignedAttachmetRequest =
      !credentialRequest.binding_proof?.didcomm_signed_attachment ||
      (credentialRequest.binding_proof?.didcomm_signed_attachment &&
        credentialOffer.bindingMethod?.didcommSignedAttachment)

    return Boolean(validLinkSecretRequest && validDidCommSignedAttachmetRequest)
  }

  public async shouldAutoRespondToCredential(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { credentialRecord, requestAttachment, credentialAttachment }: CredentialFormatAutoRespondCredentialOptions
  ) {
    return true
  }

  private async createDataIntegrityCredentialOffer(
    agentContext: AgentContext,
    credentialRecord: CredentialExchangeRecord,
    options: DataIntegrityOfferCredentialFormat
  ): Promise<{
    dataIntegrityCredentialOffer: DataIntegrityCredentialOffer
    previewAttributes: CredentialPreviewAttributeOptions[]
  }> {
    const {
      bindingRequired,
      credential,
      anonCredsLinkSecretBinding: anonCredsLinkSecretBindingMethodOptions,
      didCommSignedAttachmentBinding: didCommSignedAttachmentBindingMethodOptions,
    } = options

    const dataModelVersionsSupported: W3C_VC_DATA_MODEL_VERSION[] = ['1.1']

    // validate the credential and get the preview attributes
    const credentialJson = credential instanceof W3cCredential ? JsonTransformer.toJSON(credential) : credential
    const validW3cCredential = JsonTransformer.fromJSON(credentialJson, W3cCredential)
    const previewAttributes = this.previewAttributesFromCredential(validW3cCredential)

    let anonCredsLinkSecretBindingMethod: AnonCredsLinkSecretBindingMethod | undefined = undefined
    if (anonCredsLinkSecretBindingMethodOptions) {
      const { credentialDefinitionId, revocationRegistryDefinitionId, revocationRegistryIndex } =
        anonCredsLinkSecretBindingMethodOptions

      const anoncredsCredentialOffer = await agentContext.dependencyManager
        .resolve<AnonCredsIssuerService>(AnonCredsIssuerServiceSymbol)
        .createCredentialOffer(agentContext, { credentialDefinitionId })

      // We check locally for credential definition info. If it supports revocation, revocationRegistryIndex
      // and revocationRegistryDefinitionId are mandatory
      const { credentialDefinition } = await agentContext.dependencyManager
        .resolve(AnonCredsCredentialDefinitionRepository)
        .getByCredentialDefinitionId(agentContext, anoncredsCredentialOffer.cred_def_id)

      if (credentialDefinition.value.revocation) {
        if (!revocationRegistryDefinitionId || !revocationRegistryIndex) {
          throw new CredoError(
            'AnonCreds revocable credentials require revocationRegistryDefinitionId and revocationRegistryIndex'
          )
        }

        // Set revocation tags
        credentialRecord.setTags({
          anonCredsRevocationRegistryId: revocationRegistryDefinitionId,
          anonCredsCredentialRevocationId: revocationRegistryIndex.toString(),
        })
      }

      await this.assertCredentialAttributesMatchSchemaAttributes(
        agentContext,
        validW3cCredential,
        credentialDefinition.schemaId,
        false
      )

      anonCredsLinkSecretBindingMethod = {
        credentialDefinitionId: anoncredsCredentialOffer.cred_def_id,
        keyCorrectnessProof: anoncredsCredentialOffer.key_correctness_proof,
        nonce: anoncredsCredentialOffer.nonce,
      }

      credentialRecord.metadata.set<AnonCredsCredentialMetadata>(AnonCredsCredentialMetadataKey, {
        schemaId: anoncredsCredentialOffer.schema_id,
        credentialDefinitionId: credentialDefinitionId,
        credentialRevocationId: revocationRegistryIndex?.toString(),
        revocationRegistryId: revocationRegistryDefinitionId,
      })
    }

    let didCommSignedAttachmentBindingMethod: DidCommSignedAttachmentBindingMethod | undefined = undefined
    if (didCommSignedAttachmentBindingMethodOptions) {
      const { didMethodsSupported, algsSupported } = didCommSignedAttachmentBindingMethodOptions
      didCommSignedAttachmentBindingMethod = {
        didMethodsSupported:
          didMethodsSupported ?? agentContext.dependencyManager.resolve(DidsApi).supportedResolverMethods,
        algsSupported: algsSupported ?? this.getSupportedJwaSignatureAlgorithms(agentContext),
        nonce: await agentContext.wallet.generateNonce(),
      }

      if (didCommSignedAttachmentBindingMethod.algsSupported.length === 0) {
        throw new CredoError('No supported JWA signature algorithms found.')
      }

      if (didCommSignedAttachmentBindingMethod.didMethodsSupported.length === 0) {
        throw new CredoError('No supported DID methods found.')
      }
    }

    if (bindingRequired && !anonCredsLinkSecretBindingMethod && !didCommSignedAttachmentBindingMethod) {
      throw new CredoError('Missing required binding method.')
    }

    const dataIntegrityCredentialOffer = new DataIntegrityCredentialOffer({
      dataModelVersionsSupported,
      bindingRequired: bindingRequired,
      bindingMethod: {
        anoncredsLinkSecret: anonCredsLinkSecretBindingMethod,
        didcommSignedAttachment: didCommSignedAttachmentBindingMethod,
      },
      credential: credentialJson,
    })

    return { dataIntegrityCredentialOffer, previewAttributes }
  }

  private previewAttributesFromCredential(credential: W3cCredential): CredentialPreviewAttributeOptions[] {
    if (Array.isArray(credential.credentialSubject)) {
      throw new CredoError('Credential subject must be an object.')
    }

    const claims = {
      ...credential.credentialSubject.claims,
      ...(credential.credentialSubject.id && { id: credential.credentialSubject.id }),
    } as AnonCredsClaimRecord
    const attributes = Object.entries(claims).map(([key, value]): CredentialPreviewAttributeOptions => {
      return { name: key, value: value.toString() }
    })
    return attributes
  }

  private async assertCredentialAttributesMatchSchemaAttributes(
    agentContext: AgentContext,
    credential: W3cCredential,
    schemaId: string,
    credentialSubjectIdMustBeSet: boolean
  ) {
    const attributes = this.previewAttributesFromCredential(credential)

    const schemaReturn = await fetchSchema(agentContext, schemaId)

    const enhancedAttributes = [...attributes]
    if (
      !credentialSubjectIdMustBeSet &&
      schemaReturn.schema.attrNames.includes('id') &&
      attributes.find((attr) => attr.name === 'id') === undefined
    )
      enhancedAttributes.push({ name: 'id', value: 'mock' })
    assertAttributesMatchSchema(schemaReturn.schema, enhancedAttributes)

    return { attributes }
  }

  /**
   * Returns an object of type {@link Attachment} for use in credential exchange messages.
   * It looks up the correct format identifier and encodes the data as a base64 attachment.
   *
   * @param data The data to include in the attach object
   * @param id the attach id from the formats component of the message
   */
  public getFormatData(data: unknown, id: string): Attachment {
    const attachment = new Attachment({
      id,
      mimeType: 'application/json',
      data: {
        base64: JsonEncoder.toBase64(data),
      },
    })

    return attachment
  }

  /**
   * Returns the JWA Signature Algorithms that are supported by the wallet.
   *
   * This is an approximation based on the supported key types of the wallet.
   * This is not 100% correct as a supporting a key type does not mean you support
   * all the algorithms for that key type. However, this needs refactoring of the wallet
   * that is planned for the 0.5.0 release.
   */
  private getSupportedJwaSignatureAlgorithms(agentContext: AgentContext): JwaSignatureAlgorithm[] {
    const supportedKeyTypes = agentContext.wallet.supportedKeyTypes

    // Extract the supported JWS algs based on the key types the wallet support.
    const supportedJwaSignatureAlgorithms = supportedKeyTypes
      // Map the supported key types to the supported JWK class
      .map(getJwkClassFromKeyType)
      // Filter out the undefined values
      .filter((jwkClass): jwkClass is Exclude<typeof jwkClass, undefined> => jwkClass !== undefined)
      // Extract the supported JWA signature algorithms from the JWK class
      .flatMap((jwkClass) => jwkClass.supportedSignatureAlgorithms)

    return supportedJwaSignatureAlgorithms
  }
}
