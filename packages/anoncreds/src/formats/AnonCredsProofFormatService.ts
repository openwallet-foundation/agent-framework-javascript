import type {
  AnonCredsProofFormat,
  AnonCredsCredentialsForProofRequest,
  AnonCredsGetCredentialsForProofRequestOptions,
} from './AnonCredsProofFormat'
import type {
  AnonCredsCredentialDefinition,
  AnonCredsCredentialInfo,
  AnonCredsProof,
  AnonCredsRequestedAttribute,
  AnonCredsRequestedAttributeMatch,
  AnonCredsRequestedPredicate,
  AnonCredsRequestedPredicateMatch,
  AnonCredsSchema,
  AnonCredsSelectedCredentials,
  AnonCredsProofRequest,
} from '../models'
import type { AnonCredsHolderService, AnonCredsVerifierService, GetCredentialsForProofRequestReturn } from '../services'
import type {
  ProofFormatService,
  AgentContext,
  ProofFormatCreateReturn,
  FormatCreateRequestOptions,
  ProofFormatCreateProposalOptions,
  ProofFormatProcessOptions,
  ProofFormatAcceptProposalOptions,
  ProofFormatAcceptRequestOptions,
  ProofFormatProcessPresentationOptions,
  ProofFormatGetCredentialsForRequestOptions,
  ProofFormatGetCredentialsForRequestReturn,
  ProofFormatSelectCredentialsForRequestOptions,
  ProofFormatSelectCredentialsForRequestReturn,
  ProofFormatAutoRespondProposalOptions,
  ProofFormatAutoRespondRequestOptions,
  ProofFormatAutoRespondPresentationOptions,
} from '@aries-framework/core'

import {
  AriesFrameworkError,
  Attachment,
  AttachmentData,
  JsonEncoder,
  ProofFormatSpec,
  JsonTransformer,
} from '@aries-framework/core'

import { AnonCredsProofRequest as AnonCredsProofRequestClass } from '../models/AnonCredsProofRequest'
import { AnonCredsVerifierServiceSymbol, AnonCredsHolderServiceSymbol } from '../services'
import { AnonCredsRegistryService } from '../services/registry/AnonCredsRegistryService'
import {
  sortRequestedCredentialsMatches,
  createRequestFromPreview,
  areAnonCredsProofRequestsEqual,
  assertBestPracticeRevocationInterval,
  checkValidCredentialValueEncoding,
  encodeCredentialValue,
  assertNoDuplicateGroupsNamesInProofRequest,
  getRevocationRegistriesForRequest,
  getRevocationRegistriesForProof,
} from '../utils'
import { dateToTimestamp } from '../utils/timestamp'

const ANONCREDS_PRESENTATION_PROPOSAL = 'anoncreds/proof-request@v1.0'
const ANONCREDS_PRESENTATION_REQUEST = 'anoncreds/proof-request@v1.0'
const ANONCREDS_PRESENTATION = 'anoncreds/proof@v1.0'

export class AnonCredsProofFormatService implements ProofFormatService<AnonCredsProofFormat> {
  public readonly formatKey = 'anoncreds' as const

  public async createProposal(
    agentContext: AgentContext,
    { attachmentId, proofFormats }: ProofFormatCreateProposalOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const format = new ProofFormatSpec({
      format: ANONCREDS_PRESENTATION_PROPOSAL,
      attachmentId,
    })

    const anoncredsFormat = proofFormats.anoncreds
    if (!anoncredsFormat) {
      throw Error('Missing anoncreds format to create proposal attachment format')
    }

    const proofRequest = createRequestFromPreview({
      attributes: anoncredsFormat.attributes ?? [],
      predicates: anoncredsFormat.predicates ?? [],
      name: anoncredsFormat.name ?? 'Proof request',
      version: anoncredsFormat.version ?? '1.0',
      nonce: await agentContext.wallet.generateNonce(),
      nonRevokedInterval: anoncredsFormat.nonRevokedInterval,
    })
    const attachment = this.getFormatData(proofRequest, format.attachmentId)

    return { attachment, format }
  }

  public async processProposal(agentContext: AgentContext, { attachment }: ProofFormatProcessOptions): Promise<void> {
    const proposalJson = attachment.getDataAsJson<AnonCredsProofRequest>()

    // fromJson also validates
    JsonTransformer.fromJSON(proposalJson, AnonCredsProofRequestClass)

    // Assert attribute and predicate (group) names do not match
    assertNoDuplicateGroupsNamesInProofRequest(proposalJson)
  }

  public async acceptProposal(
    agentContext: AgentContext,
    { proposalAttachment, attachmentId }: ProofFormatAcceptProposalOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const format = new ProofFormatSpec({
      format: ANONCREDS_PRESENTATION_REQUEST,
      attachmentId,
    })

    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsProofRequest>()

    const request = {
      ...proposalJson,
      // We never want to reuse the nonce from the proposal, as this will allow replay attacks
      nonce: await agentContext.wallet.generateNonce(),
    }

    const attachment = this.getFormatData(request, format.attachmentId)

    return { attachment, format }
  }

  public async createRequest(
    agentContext: AgentContext,
    { attachmentId, proofFormats }: FormatCreateRequestOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const format = new ProofFormatSpec({
      format: ANONCREDS_PRESENTATION_REQUEST,
      attachmentId,
    })

    const anoncredsFormat = proofFormats.anoncreds
    if (!anoncredsFormat) {
      throw Error('Missing anoncreds format in create request attachment format')
    }

    const request = {
      name: anoncredsFormat.name,
      version: anoncredsFormat.version,
      nonce: await agentContext.wallet.generateNonce(),
      requested_attributes: anoncredsFormat.requested_attributes ?? {},
      requested_predicates: anoncredsFormat.requested_predicates ?? {},
      non_revoked: anoncredsFormat.non_revoked,
    } satisfies AnonCredsProofRequest

    // Assert attribute and predicate (group) names do not match
    assertNoDuplicateGroupsNamesInProofRequest(request)

    const attachment = this.getFormatData(request, format.attachmentId)

    return { attachment, format }
  }

  public async processRequest(agentContext: AgentContext, { attachment }: ProofFormatProcessOptions): Promise<void> {
    const requestJson = attachment.getDataAsJson<AnonCredsProofRequest>()

    // fromJson also validates
    JsonTransformer.fromJSON(requestJson, AnonCredsProofRequestClass)

    // Assert attribute and predicate (group) names do not match
    assertNoDuplicateGroupsNamesInProofRequest(requestJson)
  }

  public async acceptRequest(
    agentContext: AgentContext,
    { proofFormats, requestAttachment, attachmentId }: ProofFormatAcceptRequestOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const format = new ProofFormatSpec({
      format: ANONCREDS_PRESENTATION,
      attachmentId,
    })
    const requestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    const anoncredsFormat = proofFormats?.anoncreds

    const selectedCredentials =
      anoncredsFormat ??
      (await this._selectCredentialsForRequest(agentContext, requestJson, {
        filterByNonRevocationRequirements: true,
      }))

    const proof = await this.createProof(agentContext, requestJson, selectedCredentials)
    const attachment = this.getFormatData(proof, format.attachmentId)

    return {
      attachment,
      format,
    }
  }

  public async processPresentation(
    agentContext: AgentContext,
    { requestAttachment, attachment }: ProofFormatProcessPresentationOptions
  ): Promise<boolean> {
    const verifierService =
      agentContext.dependencyManager.resolve<AnonCredsVerifierService>(AnonCredsVerifierServiceSymbol)

    const proofRequestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    // NOTE: we don't do validation here, as this is handled by the AnonCreds implementation, however
    // this can lead to confusing error messages. We should consider doing validation here as well.
    // Defining a class-transformer/class-validator class seems a bit overkill, and the usage of interfaces
    // for the anoncreds package keeps things simple. Maybe we can try to use something like zod to validate
    const proofJson = attachment.getDataAsJson<AnonCredsProof>()

    for (const [referent, attribute] of Object.entries(proofJson.requested_proof.revealed_attrs)) {
      if (!checkValidCredentialValueEncoding(attribute.raw, attribute.encoded)) {
        throw new AriesFrameworkError(
          `The encoded value for '${referent}' is invalid. ` +
            `Expected '${encodeCredentialValue(attribute.raw)}'. ` +
            `Actual '${attribute.encoded}'`
        )
      }
    }

    for (const [, attributeGroup] of Object.entries(proofJson.requested_proof.revealed_attr_groups ?? {})) {
      for (const [attributeName, attribute] of Object.entries(attributeGroup.values)) {
        if (!checkValidCredentialValueEncoding(attribute.raw, attribute.encoded)) {
          throw new AriesFrameworkError(
            `The encoded value for '${attributeName}' is invalid. ` +
              `Expected '${encodeCredentialValue(attribute.raw)}'. ` +
              `Actual '${attribute.encoded}'`
          )
        }
      }
    }

    const schemas = await this.getSchemas(agentContext, new Set(proofJson.identifiers.map((i) => i.schema_id)))
    const credentialDefinitions = await this.getCredentialDefinitions(
      agentContext,
      new Set(proofJson.identifiers.map((i) => i.cred_def_id))
    )

    const revocationRegistries = await getRevocationRegistriesForProof(agentContext, proofJson)

    return await verifierService.verifyProof(agentContext, {
      proofRequest: proofRequestJson,
      proof: proofJson,
      schemas,
      credentialDefinitions,
      revocationRegistries,
    })
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    { requestAttachment, proofFormats }: ProofFormatGetCredentialsForRequestOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatGetCredentialsForRequestReturn<AnonCredsProofFormat>> {
    const proofRequestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    // Set default values
    const { filterByNonRevocationRequirements = true } = proofFormats?.anoncreds ?? {}

    const credentialsForRequest = await this._getCredentialsForRequest(agentContext, proofRequestJson, {
      filterByNonRevocationRequirements,
    })

    return credentialsForRequest
  }

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    { requestAttachment, proofFormats }: ProofFormatSelectCredentialsForRequestOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatSelectCredentialsForRequestReturn<AnonCredsProofFormat>> {
    const proofRequestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    // Set default values
    const { filterByNonRevocationRequirements = true } = proofFormats?.anoncreds ?? {}

    const selectedCredentials = this._selectCredentialsForRequest(agentContext, proofRequestJson, {
      filterByNonRevocationRequirements,
    })

    return selectedCredentials
  }

  public async shouldAutoRespondToProposal(
    agentContext: AgentContext,
    { proposalAttachment, requestAttachment }: ProofFormatAutoRespondProposalOptions
  ): Promise<boolean> {
    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsProofRequest>()
    const requestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    const areRequestsEqual = areAnonCredsProofRequestsEqual(proposalJson, requestJson)
    agentContext.config.logger.debug(`AnonCreds request and proposal are are equal: ${areRequestsEqual}`, {
      proposalJson,
      requestJson,
    })

    return areRequestsEqual
  }

  public async shouldAutoRespondToRequest(
    agentContext: AgentContext,
    { proposalAttachment, requestAttachment }: ProofFormatAutoRespondRequestOptions
  ): Promise<boolean> {
    const proposalJson = proposalAttachment.getDataAsJson<AnonCredsProofRequest>()
    const requestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    return areAnonCredsProofRequestsEqual(proposalJson, requestJson)
  }

  public async shouldAutoRespondToPresentation(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _options: ProofFormatAutoRespondPresentationOptions
  ): Promise<boolean> {
    // The presentation is already verified in processPresentation, so we can just return true here.
    // It's only an ack, so it's just that we received the presentation.
    return true
  }

  public supportsFormat(formatIdentifier: string): boolean {
    const supportedFormats = [ANONCREDS_PRESENTATION_PROPOSAL, ANONCREDS_PRESENTATION_REQUEST, ANONCREDS_PRESENTATION]
    return supportedFormats.includes(formatIdentifier)
  }

  private async _getCredentialsForRequest(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    options: AnonCredsGetCredentialsForProofRequestOptions
  ): Promise<AnonCredsCredentialsForProofRequest> {
    const credentialsForProofRequest: AnonCredsCredentialsForProofRequest = {
      attributes: {},
      predicates: {},
    }

    for (const [referent, requestedAttribute] of Object.entries(proofRequest.requested_attributes)) {
      const credentials = await this.getCredentialsForProofRequestReferent(agentContext, proofRequest, referent)

      credentialsForProofRequest.attributes[referent] = sortRequestedCredentialsMatches(
        await Promise.all(
          credentials.map(async (credential) => {
            const { isRevoked, timestamp } = await this.getRevocationStatus(
              agentContext,
              proofRequest,
              requestedAttribute,
              credential.credentialInfo
            )

            return {
              credentialId: credential.credentialInfo.credentialId,
              revealed: true,
              credentialInfo: credential.credentialInfo,
              timestamp,
              revoked: isRevoked,
            } satisfies AnonCredsRequestedAttributeMatch
          })
        )
      )

      // We only attach revoked state if non-revocation is requested. So if revoked is true it means
      // the credential is not applicable to the proof request
      if (options.filterByNonRevocationRequirements) {
        credentialsForProofRequest.attributes[referent] = credentialsForProofRequest.attributes[referent].filter(
          (r) => !r.revoked
        )
      }
    }

    for (const [referent, requestedPredicate] of Object.entries(proofRequest.requested_predicates)) {
      const credentials = await this.getCredentialsForProofRequestReferent(agentContext, proofRequest, referent)

      credentialsForProofRequest.predicates[referent] = sortRequestedCredentialsMatches(
        await Promise.all(
          credentials.map(async (credential) => {
            const { isRevoked, timestamp } = await this.getRevocationStatus(
              agentContext,
              proofRequest,
              requestedPredicate,
              credential.credentialInfo
            )

            return {
              credentialId: credential.credentialInfo.credentialId,
              credentialInfo: credential.credentialInfo,
              timestamp,
              revoked: isRevoked,
            } satisfies AnonCredsRequestedPredicateMatch
          })
        )
      )

      // We only attach revoked state if non-revocation is requested. So if revoked is true it means
      // the credential is not applicable to the proof request
      if (options.filterByNonRevocationRequirements) {
        credentialsForProofRequest.predicates[referent] = credentialsForProofRequest.predicates[referent].filter(
          (r) => !r.revoked
        )
      }
    }

    return credentialsForProofRequest
  }

  private async _selectCredentialsForRequest(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    options: AnonCredsGetCredentialsForProofRequestOptions
  ): Promise<AnonCredsSelectedCredentials> {
    const credentialsForRequest = await this._getCredentialsForRequest(agentContext, proofRequest, options)

    const selectedCredentials: AnonCredsSelectedCredentials = {
      attributes: {},
      predicates: {},
      selfAttestedAttributes: {},
    }

    Object.keys(credentialsForRequest.attributes).forEach((attributeName) => {
      const attributeArray = credentialsForRequest.attributes[attributeName]

      if (attributeArray.length === 0) {
        throw new AriesFrameworkError('Unable to automatically select requested attributes.')
      }

      selectedCredentials.attributes[attributeName] = attributeArray[0]
    })

    Object.keys(credentialsForRequest.predicates).forEach((attributeName) => {
      if (credentialsForRequest.predicates[attributeName].length === 0) {
        throw new AriesFrameworkError('Unable to automatically select requested predicates.')
      } else {
        selectedCredentials.predicates[attributeName] = credentialsForRequest.predicates[attributeName][0]
      }
    })

    return selectedCredentials
  }

  private async getCredentialsForProofRequestReferent(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    attributeReferent: string
  ): Promise<GetCredentialsForProofRequestReturn> {
    const holderService = agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    const credentials = await holderService.getCredentialsForProofRequest(agentContext, {
      proofRequest,
      attributeReferent,
    })

    return credentials
  }

  /**
   * Build schemas object needed to create and verify proof objects.
   *
   * Creates object with `{ schemaId: AnonCredsSchema }` mapping
   *
   * @param schemaIds List of schema ids
   * @returns Object containing schemas for specified schema ids
   *
   */
  private async getSchemas(agentContext: AgentContext, schemaIds: Set<string>) {
    const registryService = agentContext.dependencyManager.resolve(AnonCredsRegistryService)

    const schemas: { [key: string]: AnonCredsSchema } = {}

    for (const schemaId of schemaIds) {
      const schemaRegistry = registryService.getRegistryForIdentifier(agentContext, schemaId)
      const schemaResult = await schemaRegistry.getSchema(agentContext, schemaId)

      if (!schemaResult.schema) {
        throw new AriesFrameworkError(`Schema not found for id ${schemaId}: ${schemaResult.resolutionMetadata.message}`)
      }

      schemas[schemaId] = schemaResult.schema
    }

    return schemas
  }

  /**
   * Build credential definitions object needed to create and verify proof objects.
   *
   * Creates object with `{ credentialDefinitionId: AnonCredsCredentialDefinition }` mapping
   *
   * @param credentialDefinitionIds List of credential definition ids
   * @returns Object containing credential definitions for specified credential definition ids
   *
   */
  private async getCredentialDefinitions(agentContext: AgentContext, credentialDefinitionIds: Set<string>) {
    const registryService = agentContext.dependencyManager.resolve(AnonCredsRegistryService)

    const credentialDefinitions: { [key: string]: AnonCredsCredentialDefinition } = {}

    for (const credentialDefinitionId of credentialDefinitionIds) {
      const credentialDefinitionRegistry = registryService.getRegistryForIdentifier(
        agentContext,
        credentialDefinitionId
      )

      const credentialDefinitionResult = await credentialDefinitionRegistry.getCredentialDefinition(
        agentContext,
        credentialDefinitionId
      )

      if (!credentialDefinitionResult.credentialDefinition) {
        throw new AriesFrameworkError(
          `Credential definition not found for id ${credentialDefinitionId}: ${credentialDefinitionResult.resolutionMetadata.message}`
        )
      }

      credentialDefinitions[credentialDefinitionId] = credentialDefinitionResult.credentialDefinition
    }

    return credentialDefinitions
  }

  private async getRevocationStatus(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    requestedItem: AnonCredsRequestedAttribute | AnonCredsRequestedPredicate,
    credentialInfo: AnonCredsCredentialInfo
  ) {
    const requestNonRevoked = requestedItem.non_revoked ?? proofRequest.non_revoked
    const credentialRevocationId = credentialInfo.credentialRevocationId
    const revocationRegistryId = credentialInfo.revocationRegistryId

    // If revocation interval is not present or the credential is not revocable then we
    // don't need to fetch the revocation status
    if (!requestNonRevoked || !credentialRevocationId || !revocationRegistryId) {
      return { isRevoked: undefined, timestamp: undefined }
    }

    agentContext.config.logger.trace(
      `Fetching credential revocation status for credential revocation id '${credentialRevocationId}' with revocation interval with from '${requestNonRevoked.from}' and to '${requestNonRevoked.to}'`
    )

    // Make sure the revocation interval follows best practices from Aries RFC 0441
    assertBestPracticeRevocationInterval(requestNonRevoked)

    const registryService = agentContext.dependencyManager.resolve(AnonCredsRegistryService)
    const registry = registryService.getRegistryForIdentifier(agentContext, revocationRegistryId)

    const revocationStatusResult = await registry.getRevocationStatusList(
      agentContext,
      revocationRegistryId,
      requestNonRevoked.to ?? dateToTimestamp(new Date())
    )

    if (!revocationStatusResult.revocationStatusList) {
      throw new AriesFrameworkError(
        `Could not retrieve revocation status list for revocation registry ${revocationRegistryId}: ${revocationStatusResult.resolutionMetadata.message}`
      )
    }

    // Item is revoked when the value at the index is 1
    const isRevoked = revocationStatusResult.revocationStatusList.revocationList[parseInt(credentialRevocationId)] === 1

    agentContext.config.logger.trace(
      `Credential with credential revocation index '${credentialRevocationId}' is ${
        isRevoked ? '' : 'not '
      }revoked with revocation interval with to '${requestNonRevoked.to}' & from '${requestNonRevoked.from}'`
    )

    return {
      isRevoked,
      timestamp: revocationStatusResult.revocationStatusList.timestamp,
    }
  }

  /**
   * Create anoncreds proof from a given proof request and requested credential object.
   *
   * @param proofRequest The proof request to create the proof for
   * @param requestedCredentials The requested credentials object specifying which credentials to use for the proof
   * @returns anoncreds proof object
   */
  private async createProof(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    selectedCredentials: AnonCredsSelectedCredentials
  ): Promise<AnonCredsProof> {
    const holderService = agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)

    const credentialObjects = await Promise.all(
      [...Object.values(selectedCredentials.attributes), ...Object.values(selectedCredentials.predicates)].map(
        async (c) => c.credentialInfo ?? holderService.getCredential(agentContext, { credentialId: c.credentialId })
      )
    )

    const schemas = await this.getSchemas(agentContext, new Set(credentialObjects.map((c) => c.schemaId)))
    const credentialDefinitions = await this.getCredentialDefinitions(
      agentContext,
      new Set(credentialObjects.map((c) => c.credentialDefinitionId))
    )

    // selectedCredentials are overridden with specified timestamps of the revocation status list that
    // should be used for the selected credentials.
    const { revocationRegistries, updatedSelectedCredentials } = await getRevocationRegistriesForRequest(
      agentContext,
      proofRequest,
      selectedCredentials
    )

    return await holderService.createProof(agentContext, {
      proofRequest,
      selectedCredentials: updatedSelectedCredentials,
      schemas,
      credentialDefinitions,
      revocationRegistries,
    })
  }

  /**
   * Returns an object of type {@link Attachment} for use in credential exchange messages.
   * It looks up the correct format identifier and encodes the data as a base64 attachment.
   *
   * @param data The data to include in the attach object
   * @param id the attach id from the formats component of the message
   */
  private getFormatData(data: unknown, id: string): Attachment {
    const attachment = new Attachment({
      id,
      mimeType: 'application/json',
      data: new AttachmentData({
        base64: JsonEncoder.toBase64(data),
      }),
    })

    return attachment
  }
}
