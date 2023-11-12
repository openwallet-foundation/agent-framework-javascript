import type { InputDescriptorToCredentials, PresentationSubmission } from './selection/types'
import type { VpFormat } from '../OpenId4VcHolderServiceOptions'
import type {
  AgentContext,
  Query,
  VerificationMethod,
  W3cCredentialRecord,
  W3cVerifiableCredential,
  W3cVerifiablePresentation,
} from '@aries-framework/core'
import type {
  IPresentationDefinition,
  PresentationSignCallBackParams,
  VerifiablePresentationResult,
} from '@sphereon/pex'
import type {
  PresentationDefinitionV1,
  PresentationSubmission as PexPresentationSubmission,
  Descriptor,
  InputDescriptorV2,
} from '@sphereon/pex-models'
import type { OriginalVerifiableCredential } from '@sphereon/ssi-types'

import {
  AriesFrameworkError,
  ClaimFormat,
  DidsApi,
  getJwkFromKey,
  getKeyFromVerificationMethod,
  injectable,
  JsonTransformer,
  W3cCredentialService,
  W3cPresentation,
  W3cCredentialRepository,
} from '@aries-framework/core'
import { PEVersion, PEX } from '@sphereon/pex'

import { selectCredentialsForRequest } from './selection/PexCredentialSelection'
import {
  getSphereonW3cVerifiableCredential,
  getSphereonW3cVerifiablePresentation,
  getW3cVerifiablePresentationInstance,
} from './transform'

type ProofStructure = {
  [subjectId: string]: {
    [inputDescriptorId: string]: W3cVerifiableCredential[]
  }
}

@injectable()
export class PresentationExchangeService {
  private pex = new PEX()

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    presentationDefinition: IPresentationDefinition
  ): Promise<PresentationSubmission> {
    const credentialRecords = await this.queryCredentialForPresentationDefinition(agentContext, presentationDefinition)

    const didsApi = agentContext.dependencyManager.resolve(DidsApi)
    const didRecords = await didsApi.getCreatedDids()
    const holderDIDs = didRecords.map((didRecord) => didRecord.did)

    return selectCredentialsForRequest(presentationDefinition, credentialRecords, holderDIDs)
  }

  /**
   * Queries the wallet for credentials that match the given presentation definition. This only does an initial query based on the
   * schema of the input descriptors. It does not do any further filtering based on the constraints in the input descriptors.
   */
  private async queryCredentialForPresentationDefinition(
    agentContext: AgentContext,
    presentationDefinition: IPresentationDefinition
  ) {
    const w3cCredentialRepository = agentContext.dependencyManager.resolve(W3cCredentialRepository)
    const query: Array<Query<W3cCredentialRecord>> = []
    const presentationDefinitionVersion = PEX.definitionVersionDiscovery(presentationDefinition)

    if (!presentationDefinitionVersion.version) {
      throw new AriesFrameworkError(
        `Unable to determine the Presentation Exchange version from the presentation definition. ${
          presentationDefinitionVersion.error ?? 'Unknown error'
        }`
      )
    }

    if (presentationDefinitionVersion.version === PEVersion.v1) {
      const pd = presentationDefinition as PresentationDefinitionV1

      // The schema.uri can contain either an expanded type, or a context uri
      for (const inputDescriptor of pd.input_descriptors) {
        for (const schema of inputDescriptor.schema) {
          // TODO: write migration
          query.push({
            $or: [{ expandedType: [schema.uri] }, { contexts: [schema.uri] }, { type: [schema.uri] }],
          })
        }
      }
    } else if (presentationDefinitionVersion.version === PEVersion.v2) {
      // FIXME: As PE version 2 does not have the `schema` anymore, we can't query by schema anymore.
      // For now we retrieve ALL credentials, as we did the same for V1 with JWT credentials. We probably need
      // to find some way to do initial filtering, hopefully if there's a filter on the `type` field or something.
    } else {
      throw new AriesFrameworkError(
        `Unsupported presentation definition version ${presentationDefinitionVersion.version as unknown as string}`
      )
    }

    // query the wallet ourselves first to avoid the need to query the pex library for all
    // credentials for every proof request
    const credentialRecords = await w3cCredentialRepository.findByQuery(agentContext, {
      $or: query,
    })

    return credentialRecords
  }

  private addCredentialToSubjectInputDescriptor(
    subjectsToInputDescriptors: ProofStructure,
    subjectId: string,
    inputDescriptorId: string,
    credential: W3cVerifiableCredential
  ) {
    const inputDescriptorsToCredentials = subjectsToInputDescriptors[subjectId] ?? {}
    const credentials = inputDescriptorsToCredentials[inputDescriptorId] ?? []

    credentials.push(credential)
    inputDescriptorsToCredentials[inputDescriptorId] = credentials
    subjectsToInputDescriptors[subjectId] = inputDescriptorsToCredentials
  }

  private getPresentationFormat(
    presentationDefinition: IPresentationDefinition,
    credentials: OriginalVerifiableCredential[]
  ): VpFormat {
    const allCredentialsAreJwtVc = credentials?.every((c) => typeof c === 'string')
    const allCredentialsAreLdpVc = credentials?.every((c) => typeof c !== 'string')

    const inputDescriptorsNotSupportingJwtVc = (presentationDefinition.input_descriptors as InputDescriptorV2[]).filter(
      (d) => d.format && d.format.jwt_vc === undefined
    )

    const inputDescriptorsNotSupportingLdpVc = (presentationDefinition.input_descriptors as InputDescriptorV2[]).filter(
      (d) => d.format && d.format.ldp_vc === undefined
    )

    if (
      allCredentialsAreJwtVc &&
      (presentationDefinition.format === undefined || presentationDefinition.format.jwt_vc) &&
      inputDescriptorsNotSupportingJwtVc.length === 0
    ) {
      return 'jwt_vp'
    } else if (
      allCredentialsAreLdpVc &&
      (presentationDefinition.format === undefined || presentationDefinition.format.ldp_vc) &&
      inputDescriptorsNotSupportingLdpVc.length === 0
    ) {
      return 'ldp_vp'
    } else {
      throw new AriesFrameworkError(
        'No suitable presentation format found for the given presentation definition, and credentials'
      )
    }
  }

  public async createPresentation(
    agentContext: AgentContext,
    options: {
      credentialsForInputDescriptor: InputDescriptorToCredentials
      presentationDefinition: IPresentationDefinition
      challenge?: string
      domain?: string
      nonce?: string
    }
  ) {
    const { presentationDefinition, challenge, nonce, domain } = options

    const proofStructure: ProofStructure = {}

    Object.entries(options.credentialsForInputDescriptor).forEach(([inputDescriptorId, credentials]) => {
      credentials.forEach((credential) => {
        const subjectId = credential.credentialSubjectIds[0]
        if (!subjectId) {
          throw new AriesFrameworkError('Missing required credential subject for creating the presentation.')
        }

        this.addCredentialToSubjectInputDescriptor(proofStructure, subjectId, inputDescriptorId, credential)
      })
    })

    const verifiablePresentationResultsWithFormat: {
      verifiablePresentationResult: VerifiablePresentationResult
      format: VpFormat
    }[] = []

    const subjectToInputDescriptors = Object.entries(proofStructure)
    for (const [subjectId, subjectInputDescriptorsToCredentials] of subjectToInputDescriptors) {
      // Determine a suitable verification method for the presentation
      const verificationMethod = await this.getVerificationMethodForSubjectId(agentContext, subjectId)

      if (!verificationMethod) {
        throw new AriesFrameworkError(`No verification method found for subject id '${subjectId}'.`)
      }

      // We create a presentation for each subject
      // Thus for each subject we need to filter all the related input descriptors and credentials
      // FIXME: cast to V1, as tsc errors for strange reasons if not
      const inputDescriptorsForSubject = (presentationDefinition as PresentationDefinitionV1).input_descriptors.filter(
        (inputDescriptor) => inputDescriptor.id in subjectInputDescriptorsToCredentials
      )

      // Get all the credentials associated with the input descriptors
      const credentialsForSubject = Object.values(subjectInputDescriptorsToCredentials)
        .flatMap((credentials) => credentials)
        .map(getSphereonW3cVerifiableCredential)

      const presentationDefinitionForSubject: IPresentationDefinition = {
        ...presentationDefinition,
        input_descriptors: inputDescriptorsForSubject,

        // We remove the submission requirements, as it will otherwise fail to create the VP
        // TODO: Will this cause issue for creating the credential? Need to run tests
        submission_requirements: undefined,
      }

      const format = this.getPresentationFormat(presentationDefinitionForSubject, credentialsForSubject)

      // FIXME: Q1: is holder always subject id, what if there are multiple subjects???
      // FIXME: Q2: What about proofType, proofPurpose verification method for multiple subjects?
      const verifiablePresentationResult = await this.pex.verifiablePresentationFrom(
        presentationDefinitionForSubject,
        credentialsForSubject,
        this.getPresentationSignCallback(agentContext, verificationMethod, format),
        {
          holderDID: subjectId,
          proofOptions: { challenge, domain, nonce },
          signatureOptions: { verificationMethod: verificationMethod?.id },
        }
      )

      verifiablePresentationResultsWithFormat.push({ verifiablePresentationResult, format })
    }

    if (!verifiablePresentationResultsWithFormat[0]) {
      throw new AriesFrameworkError('No verifiable presentations created.')
    }

    if (subjectToInputDescriptors.length !== verifiablePresentationResultsWithFormat.length) {
      throw new AriesFrameworkError('Invalid amount of verifiable presentations created.')
    }

    const presentationSubmission: PexPresentationSubmission = {
      id: verifiablePresentationResultsWithFormat[0].verifiablePresentationResult.presentationSubmission.id,
      definition_id:
        verifiablePresentationResultsWithFormat[0].verifiablePresentationResult.presentationSubmission.definition_id,
      descriptor_map: [],
    }

    for (const [index, vp] of verifiablePresentationResultsWithFormat.entries()) {
      presentationSubmission.descriptor_map.push(
        ...vp.verifiablePresentationResult.presentationSubmission.descriptor_map.map((descriptor): Descriptor => {
          const prefix = verifiablePresentationResultsWithFormat.length > 1 ? `$[${index}]` : '$'
          return {
            format: vp.format,
            path: prefix,
            id: descriptor.id,
            path_nested: {
              ...descriptor,
              path: descriptor.path.replace('$.', `${prefix}.vp.`),
              format: 'jwt_vc_json', // TODO: why jwt_vc_json
            },
          }
        })
      )
    }

    return {
      verifiablePresentations: verifiablePresentationResultsWithFormat.map((r) =>
        getW3cVerifiablePresentationInstance(r.verifiablePresentationResult.verifiablePresentation)
      ),
      presentationSubmission,
      presentationSubmissionLocation:
        verifiablePresentationResultsWithFormat[0].verifiablePresentationResult.presentationSubmissionLocation,
    }
  }

  private getSigningAlgorithmFromVerificationMethod(
    verificationMethod: VerificationMethod,
    suitableAlgorithms?: string[]
  ) {
    const key = getKeyFromVerificationMethod(verificationMethod)
    const jwk = getJwkFromKey(key)

    if (suitableAlgorithms) {
      const possibleAlgorithms = jwk.supportedSignatureAlgorithms.filter((alg) => suitableAlgorithms?.includes(alg))
      if (!possibleAlgorithms || possibleAlgorithms.length === 0) {
        throw new AriesFrameworkError(
          [
            `Found no suitable signing algorithm.`,
            `Algorithms supported by Verification method: ${jwk.supportedSignatureAlgorithms.join(', ')}`,
            `Suitable algorithms: ${suitableAlgorithms.join(', ')}`,
          ].join('\n')
        )
      }
    }

    const alg = jwk.supportedSignatureAlgorithms[0]
    if (!alg) throw new AriesFrameworkError(`No supported algs for key type: ${key.keyType}`)
    return alg
  }

  private getSigningAlgorithmsForPresentationDefinitionAndInputDescriptors(
    algorithmsSatisfyingDefinition: string[],
    inputDescriptorAlgorithms: string[][]
  ) {
    const allDescriptorAlgorithms = inputDescriptorAlgorithms.flat()
    const algorithmsSatisfyingDescriptors = allDescriptorAlgorithms.filter((alg) =>
      inputDescriptorAlgorithms.every((descriptorAlgorithmSet) => descriptorAlgorithmSet.includes(alg))
    )

    const algorithmsSatisfyingPdAndDescriptorRestrictions = algorithmsSatisfyingDefinition.filter((alg) =>
      algorithmsSatisfyingDescriptors.includes(alg)
    )

    if (
      algorithmsSatisfyingDefinition.length > 0 &&
      algorithmsSatisfyingDescriptors.length > 0 &&
      algorithmsSatisfyingPdAndDescriptorRestrictions.length === 0
    ) {
      throw new AriesFrameworkError(
        `No signature algorithm found for satisfying restrictions of the presentation definition and input descriptors.`
      )
    }

    if (allDescriptorAlgorithms.length > 0 && algorithmsSatisfyingDescriptors.length === 0) {
      throw new AriesFrameworkError(
        `No signature algorithm found for satisfying restrictions of the input descriptors.`
      )
    }

    let suitableAlgorithms: string[] | undefined = undefined
    if (algorithmsSatisfyingPdAndDescriptorRestrictions.length > 0) {
      suitableAlgorithms = algorithmsSatisfyingPdAndDescriptorRestrictions
    } else if (algorithmsSatisfyingDescriptors.length > 0) {
      suitableAlgorithms = algorithmsSatisfyingDescriptors
    } else if (algorithmsSatisfyingDefinition.length > 0) {
      suitableAlgorithms = algorithmsSatisfyingDefinition
    }

    return suitableAlgorithms
  }

  private getSigningAlgorithmForJwtVc(
    presentationDefinition: IPresentationDefinition,
    verificationMethod: VerificationMethod
  ) {
    const algorithmsSatisfyingDefinition = presentationDefinition.format?.jwt_vc?.alg || []

    const inputDescriptorAlgorithms: string[][] = presentationDefinition.input_descriptors
      .map((descriptor) => (descriptor as InputDescriptorV2).format?.jwt_vc?.alg || [])
      .filter((alg) => alg.length > 0)

    const suitableAlgorithms = this.getSigningAlgorithmsForPresentationDefinitionAndInputDescriptors(
      algorithmsSatisfyingDefinition,
      inputDescriptorAlgorithms
    )

    return this.getSigningAlgorithmFromVerificationMethod(verificationMethod, suitableAlgorithms)
  }

  private getSigningAlgorithmForLdpVc(
    presentationDefinition: IPresentationDefinition,
    verificationMethod: VerificationMethod
  ) {
    const algorithmsSatisfyingDefinition = presentationDefinition.format?.ldp_vc?.proof_type || []

    const inputDescriptorAlgorithms: string[][] = presentationDefinition.input_descriptors
      .map((descriptor) => (descriptor as InputDescriptorV2).format?.ldp_vc?.proof_type || [])
      .filter((alg) => alg.length > 0)

    const suitableAlgorithms = this.getSigningAlgorithmsForPresentationDefinitionAndInputDescriptors(
      algorithmsSatisfyingDefinition,
      inputDescriptorAlgorithms
    )

    // TODO: find out which signature suites are supported by the verification method
    // TODO: check if a supported signature suite is in the list of suitable signature suites
    return suitableAlgorithms ? suitableAlgorithms[0] : 'todo'
  }

  public getPresentationSignCallback(
    agentContext: AgentContext,
    verificationMethod: VerificationMethod,
    vpFormat: VpFormat
  ) {
    const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)

    return async (callBackParams: PresentationSignCallBackParams) => {
      // The created partial proof and presentation, as well as original supplied options
      const { presentation: presentationJson, options, presentationDefinition } = callBackParams
      const { challenge, domain, nonce } = options.proofOptions ?? {}
      const { verificationMethod: verificationMethodId } = options.signatureOptions ?? {}

      if (verificationMethodId && verificationMethodId !== verificationMethod.id) {
        throw new AriesFrameworkError(
          `Verification method from signing options ${verificationMethodId} does not match verification method ${verificationMethod.id}.`
        )
      }

      // Clients MUST ignore any presentation_submission element included inside a Verifiable Presentation.
      const presentationToSign = { ...presentationJson, presentation_submission: undefined }

      let signedPresentation: W3cVerifiablePresentation<ClaimFormat.JwtVp | ClaimFormat.LdpVp>
      if (vpFormat === 'jwt_vp') {
        signedPresentation = await w3cCredentialService.signPresentation(agentContext, {
          format: ClaimFormat.JwtVp,
          verificationMethod: verificationMethod.id,
          presentation: JsonTransformer.fromJSON(presentationToSign, W3cPresentation),
          alg: this.getSigningAlgorithmForJwtVc(presentationDefinition, verificationMethod),
          challenge: challenge ?? nonce ?? (await agentContext.wallet.generateNonce()),
          domain,
        })
      } else if (vpFormat === 'ldp_vp') {
        signedPresentation = await w3cCredentialService.signPresentation(agentContext, {
          format: ClaimFormat.LdpVp,
          proofType: this.getSigningAlgorithmForLdpVc(presentationDefinition, verificationMethod),
          proofPurpose: 'authentication',
          verificationMethod: verificationMethod.id,
          presentation: JsonTransformer.fromJSON(presentationToSign, W3cPresentation),
          challenge: challenge ?? nonce ?? (await agentContext.wallet.generateNonce()),
          domain,
        })
      } else {
        throw new AriesFrameworkError(
          `Only JWT credentials or JSONLD credentials are supported for a single presentation.`
        )
      }

      return getSphereonW3cVerifiablePresentation(signedPresentation)
    }
  }

  private async getVerificationMethodForSubjectId(agentContext: AgentContext, subjectId: string) {
    const didsApi = agentContext.dependencyManager.resolve(DidsApi)

    if (!subjectId.startsWith('did:')) {
      throw new AriesFrameworkError(`Only dids are supported as credentialSubject id. ${subjectId} is not a valid did`)
    }

    const didDocument = await didsApi.resolveDidDocument(subjectId)

    if (!didDocument.authentication || didDocument.authentication.length === 0) {
      throw new AriesFrameworkError(`No authentication verificationMethods found for did ${subjectId} in did document`)
    }

    // the signature suite to use for the presentation is dependant on the credentials we share.
    // 1. Get the verification method for this given proof purpose in this DID document
    let [verificationMethod] = didDocument.authentication
    if (typeof verificationMethod === 'string') {
      verificationMethod = didDocument.dereferenceKey(verificationMethod, ['authentication'])
    }

    return verificationMethod
  }
}
