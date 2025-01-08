import type { AnonCredsProofFormat, AnonCredsGetCredentialsForProofRequestOptions } from './AnonCredsProofFormat'
import type {
  AnonCredsCredentialDefinition,
  AnonCredsProof,
  AnonCredsSchema,
  AnonCredsSelectedCredentials,
  AnonCredsProofRequest,
} from '../models'
import type { AnonCredsHolderService, AnonCredsVerifierService } from '../services'
import type { AgentContext } from '@credo-ts/core'
import type {
  ProofFormatService,
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
} from '@credo-ts/didcomm'

import { CredoError, JsonEncoder, JsonTransformer } from '@credo-ts/core'
import { Attachment, AttachmentData, ProofFormatSpec } from '@credo-ts/didcomm'

import { AnonCredsProofRequest as AnonCredsProofRequestClass } from '../models/AnonCredsProofRequest'
import { AnonCredsVerifierServiceSymbol, AnonCredsHolderServiceSymbol } from '../services'
import {
  createRequestFromPreview,
  areAnonCredsProofRequestsEqual,
  checkValidCredentialValueEncoding,
  assertNoDuplicateGroupsNamesInProofRequest,
  getRevocationRegistriesForRequest,
  getRevocationRegistriesForProof,
  fetchSchema,
  fetchCredentialDefinition,
} from '../utils'
import { encodeCredentialValue } from '../utils/credential'
import { getCredentialsForAnonCredsProofRequest } from '../utils/getCredentialsForAnonCredsRequest'

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
        throw new CredoError(
          `The encoded value for '${referent}' is invalid. ` +
            `Expected '${encodeCredentialValue(attribute.raw)}'. ` +
            `Actual '${attribute.encoded}'`
        )
      }
    }

    for (const [, attributeGroup] of Object.entries(proofJson.requested_proof.revealed_attr_groups ?? {})) {
      for (const [attributeName, attribute] of Object.entries(attributeGroup.values)) {
        if (!checkValidCredentialValueEncoding(attribute.raw, attribute.encoded)) {
          throw new CredoError(
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

    const verified = await verifierService.verifyProof(agentContext, {
      proofRequest: proofRequestJson,
      proof: proofJson,
      schemas,
      credentialDefinitions,
      revocationRegistries,
    })

    return verified
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    { requestAttachment, proofFormats }: ProofFormatGetCredentialsForRequestOptions<AnonCredsProofFormat>
  ): Promise<ProofFormatGetCredentialsForRequestReturn<AnonCredsProofFormat>> {
    const proofRequestJson = requestAttachment.getDataAsJson<AnonCredsProofRequest>()

    // Set default values
    const { filterByNonRevocationRequirements = true } = proofFormats?.anoncreds ?? {}

    const credentialsForRequest = await getCredentialsForAnonCredsProofRequest(agentContext, proofRequestJson, {
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

  private async _selectCredentialsForRequest(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    options: AnonCredsGetCredentialsForProofRequestOptions
  ): Promise<AnonCredsSelectedCredentials> {
    const credentialsForRequest = await getCredentialsForAnonCredsProofRequest(agentContext, proofRequest, options)

    const selectedCredentials: AnonCredsSelectedCredentials = {
      attributes: {},
      predicates: {},
      selfAttestedAttributes: {},
    }

    Object.keys(credentialsForRequest.attributes).forEach((attributeName) => {
      const attributeArray = credentialsForRequest.attributes[attributeName]

      if (attributeArray.length === 0) {
        throw new CredoError('Unable to automatically select requested attributes.')
      }

      selectedCredentials.attributes[attributeName] = attributeArray[0]
    })

    Object.keys(credentialsForRequest.predicates).forEach((attributeName) => {
      if (credentialsForRequest.predicates[attributeName].length === 0) {
        throw new CredoError('Unable to automatically select requested predicates.')
      } else {
        selectedCredentials.predicates[attributeName] = credentialsForRequest.predicates[attributeName][0]
      }
    })

    return selectedCredentials
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
    const schemas: { [key: string]: AnonCredsSchema } = {}

    for (const schemaId of schemaIds) {
      const { schema } = await fetchSchema(agentContext, schemaId)
      schemas[schemaId] = schema
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
    const credentialDefinitions: { [key: string]: AnonCredsCredentialDefinition } = {}

    for (const credentialDefinitionId of credentialDefinitionIds) {
      const { credentialDefinition } = await fetchCredentialDefinition(agentContext, credentialDefinitionId)
      credentialDefinitions[credentialDefinitionId] = credentialDefinition
    }

    return credentialDefinitions
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
        async (c) => c.credentialInfo ?? holderService.getCredential(agentContext, { id: c.credentialId })
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
