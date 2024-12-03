import type { W3cJsonLdDeriveProofOptions } from './deriveProof'
import type { AgentContext } from '../../../agent/context'
import type { Key } from '../../../crypto/Key'
import type { SingleOrArray } from '../../../utils'
import type {
  RevokeCredentialOptions,
  W3cJsonLdSignCredentialOptions,
  W3cJsonLdSignPresentationOptions,
  W3cJsonLdVerifyCredentialOptions,
  W3cJsonLdVerifyPresentationOptions,
} from '../W3cCredentialServiceOptions'
import type { W3cVerifyCredentialResult, W3cVerifyPresentationResult } from '../models'
import type { W3cJsonCredential } from '../models/credential/W3cJsonCredential'

import { createWalletKeyPairClass } from '../../../crypto/WalletKeyPair'
import { CredoError } from '../../../error'
import { injectable } from '../../../plugins'
import { asArray, JsonTransformer } from '../../../utils'
import { VerificationMethod } from '../../dids'
import { getKeyFromVerificationMethod } from '../../dids/domain/key-type'
import { W3cCredentialsModuleConfig } from '../W3cCredentialsModuleConfig'
import { validateStatus } from '../models/credential/status-list/W3cCredentialStatus'
import { w3cDate } from '../util'

import { SignatureSuiteRegistry } from './SignatureSuiteRegistry'
import { deriveProof } from './deriveProof'
import { assertOnlyW3cJsonLdVerifiableCredentials } from './jsonldUtil'
import jsonld from './libraries/jsonld'
import vc from './libraries/vc'
import { W3cJsonLdVerifiableCredential } from './models'
import { W3cJsonLdVerifiablePresentation } from './models/W3cJsonLdVerifiablePresentation'

/**
 * Supports signing and verification of credentials according to the [Verifiable Credential Data Model](https://www.w3.org/TR/vc-data-model)
 * using [Data Integrity Proof](https://www.w3.org/TR/vc-data-model/#data-integrity-proofs).
 */
@injectable()
export class W3cJsonLdCredentialService {
  private signatureSuiteRegistry: SignatureSuiteRegistry
  private w3cCredentialsModuleConfig: W3cCredentialsModuleConfig

  public constructor(
    signatureSuiteRegistry: SignatureSuiteRegistry,
    w3cCredentialsModuleConfig: W3cCredentialsModuleConfig
  ) {
    this.signatureSuiteRegistry = signatureSuiteRegistry
    this.w3cCredentialsModuleConfig = w3cCredentialsModuleConfig
  }

  /**
   * Signs a credential
   */
  public async signCredential(
    agentContext: AgentContext,
    options: W3cJsonLdSignCredentialOptions
  ): Promise<W3cJsonLdVerifiableCredential> {
    const WalletKeyPair = createWalletKeyPairClass(agentContext.wallet)

    const signingKey = await this.getPublicKeyFromVerificationMethod(agentContext, options.verificationMethod)
    const suiteInfo = this.signatureSuiteRegistry.getByProofType(options.proofType)

    if (!suiteInfo.keyTypes.includes(signingKey.keyType)) {
      throw new CredoError('The key type of the verification method does not match the suite')
    }

    const keyPair = new WalletKeyPair({
      controller: options.credential.issuerId, // should we check this against the verificationMethod.controller?
      id: options.verificationMethod,
      key: signingKey,
      wallet: agentContext.wallet,
    })

    const SuiteClass = suiteInfo.suiteClass

    const suite = new SuiteClass({
      key: keyPair,
      LDKeyClass: WalletKeyPair,
      proof: {
        verificationMethod: options.verificationMethod,
      },
      useNativeCanonize: false,
      date: options.created ?? w3cDate(),
    })

    const result = await vc.issue({
      credential: JsonTransformer.toJSON(options.credential),
      suite: suite,
      purpose: options.proofPurpose,
      documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
    })

    return JsonTransformer.fromJSON(result, W3cJsonLdVerifiableCredential)
  }

  /**
   * Verifies the signature(s) of a credential
   *
   * @param credential the credential to be verified
   * @returns the verification result
   */
  public async verifyCredential(
    agentContext: AgentContext,
    options: W3cJsonLdVerifyCredentialOptions
  ): Promise<W3cVerifyCredentialResult> {
    try {
      const verifyCredentialStatus = options.verifyCredentialStatus ?? true

      const suites = this.getSignatureSuitesForCredential(agentContext, options.credential)

      const verifyOptions: Record<string, unknown> = {
        credential: JsonTransformer.toJSON(options.credential),
        suite: suites,
        documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
        checkStatus: async ({ credential }: { credential: W3cJsonCredential }) => {
          if (verifyCredentialStatus && credential.credentialStatus) {
            // await verifyBitStringCredentialStatus(credential, agentContext)
            // Add a verification function that then checks which type of credentailStatus we have
            // If the type is supported, we validate it and return the result
            await validateStatus(credential.credentialStatus, agentContext)
          }
          return {
            verified: true,
          }
        },
      }

      // this is a hack because vcjs throws if purpose is passed as undefined or null
      if (options.proofPurpose) {
        verifyOptions['purpose'] = options.proofPurpose
      }

      const result = await vc.verifyCredential(verifyOptions)

      const { verified: isValid, ...remainingResult } = result

      if (!isValid) {
        agentContext.config.logger.debug(`Credential verification failed: ${result.error?.message}`, {
          stack: result.error?.stack,
        })
      }

      // We map the result to our own result type to make it easier to work with
      // however, for now we just add a single vcJs validation result as we don't
      // have access to the internal validation results of vc-js
      return {
        isValid,
        validations: {
          vcJs: {
            isValid,
            ...remainingResult,
          },
        },
        error: result.error,
      }
    } catch (error) {
      return {
        isValid: false,
        validations: {},
        error,
      }
    }
  }

  /**
   * Signs a presentation including the credentials it includes
   *
   * @param presentation the presentation to be signed
   * @returns the signed presentation
   */
  public async signPresentation(
    agentContext: AgentContext,
    options: W3cJsonLdSignPresentationOptions
  ): Promise<W3cJsonLdVerifiablePresentation> {
    // create keyPair
    const WalletKeyPair = createWalletKeyPairClass(agentContext.wallet)

    const suiteInfo = this.signatureSuiteRegistry.getByProofType(options.proofType)

    if (!suiteInfo) {
      throw new CredoError(`The requested proofType ${options.proofType} is not supported`)
    }

    const signingKey = await this.getPublicKeyFromVerificationMethod(agentContext, options.verificationMethod)

    if (!suiteInfo.keyTypes.includes(signingKey.keyType)) {
      throw new CredoError('The key type of the verification method does not match the suite')
    }

    const documentLoader = this.w3cCredentialsModuleConfig.documentLoader(agentContext)
    const verificationMethodObject = (await documentLoader(options.verificationMethod)).document as Record<
      string,
      unknown
    >

    const keyPair = new WalletKeyPair({
      controller: verificationMethodObject['controller'] as string,
      id: options.verificationMethod,
      key: signingKey,
      wallet: agentContext.wallet,
    })

    const suite = new suiteInfo.suiteClass({
      LDKeyClass: WalletKeyPair,
      proof: {
        verificationMethod: options.verificationMethod,
      },
      date: new Date().toISOString(),
      key: keyPair,
      useNativeCanonize: false,
    })

    const result = await vc.signPresentation({
      presentation: JsonTransformer.toJSON(options.presentation),
      suite: suite,
      challenge: options.challenge,
      domain: options.domain,
      documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
    })

    return JsonTransformer.fromJSON(result, W3cJsonLdVerifiablePresentation)
  }

  /**
   * Verifies a presentation including the credentials it includes
   *
   * @param presentation the presentation to be verified
   * @returns the verification result
   */
  public async verifyPresentation(
    agentContext: AgentContext,
    options: W3cJsonLdVerifyPresentationOptions
  ): Promise<W3cVerifyPresentationResult> {
    try {
      // create keyPair
      const WalletKeyPair = createWalletKeyPairClass(agentContext.wallet)

      let proofs = options.presentation.proof

      if (!Array.isArray(proofs)) {
        proofs = [proofs]
      }
      if (options.purpose) {
        proofs = proofs.filter((proof) => proof.proofPurpose === options.purpose.term)
      }

      const presentationSuites = proofs.map((proof) => {
        const SuiteClass = this.signatureSuiteRegistry.getByProofType(proof.type).suiteClass
        return new SuiteClass({
          LDKeyClass: WalletKeyPair,
          proof: {
            verificationMethod: proof.verificationMethod,
          },
          date: proof.created,
          useNativeCanonize: false,
        })
      })

      const credentials = asArray(options.presentation.verifiableCredential)
      assertOnlyW3cJsonLdVerifiableCredentials(credentials)

      const credentialSuites = credentials.map((credential) =>
        this.getSignatureSuitesForCredential(agentContext, credential)
      )
      const allSuites = presentationSuites.concat(...credentialSuites)

      const verifyCredentialStatus = options.verifyCredentialStatus ?? true
      const verifyOptions: Record<string, unknown> = {
        presentation: JsonTransformer.toJSON(options.presentation),
        suite: allSuites,
        challenge: options.challenge,
        domain: options.domain,
        documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
        checkStatus: async ({ credential }: { credential: W3cJsonCredential }) => {
          if (verifyCredentialStatus && credential.credentialStatus) {
            // await verifyBitStringCredentialStatus(credential, agentContext)
            // Add a verification function that then checks which type of credentailStatus we have
            // If the type is supported, we validate it and return the result
            await validateStatus(credential.credentialStatus, agentContext)
          }
          return {
            verified: true,
          }
        },
      }

      // this is a hack because vcjs throws if purpose is passed as undefined or null
      if (options.purpose) {
        verifyOptions['presentationPurpose'] = options.purpose
      }

      const result = await vc.verify(verifyOptions)

      const { verified: isValid, ...remainingResult } = result

      // We map the result to our own result type to make it easier to work with
      // however, for now we just add a single vcJs validation result as we don't
      // have access to the internal validation results of vc-js
      return {
        isValid,
        validations: {
          vcJs: {
            isValid,
            ...remainingResult,
          },
        },
        error: result.error,
      }
    } catch (error) {
      return {
        isValid: false,
        validations: {},
        error,
      }
    }
  }

  public async deriveProof(
    agentContext: AgentContext,
    options: W3cJsonLdDeriveProofOptions
  ): Promise<W3cJsonLdVerifiableCredential> {
    // TODO: make suite dynamic
    const suiteInfo = this.signatureSuiteRegistry.getByProofType('BbsBlsSignatureProof2020')
    const SuiteClass = suiteInfo.suiteClass

    const suite = new SuiteClass()

    const proof = await deriveProof(JsonTransformer.toJSON(options.credential), options.revealDocument, {
      suite: suite,
      documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
    })

    return proof
  }

  // temporarily disable no unused var
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async revokeCredential(_agentContext: AgentContext, _options: RevokeCredentialOptions) {
    // revoke jwt cred
    throw new CredoError(`Revocation support not implemented for JsonLd`)
  }

  public getVerificationMethodTypesByProofType(proofType: string): string[] {
    return this.signatureSuiteRegistry.getByProofType(proofType).verificationMethodTypes
  }

  public getKeyTypesByProofType(proofType: string): string[] {
    return this.signatureSuiteRegistry.getByProofType(proofType).keyTypes
  }

  public async getExpandedTypesForCredential(agentContext: AgentContext, credential: W3cJsonLdVerifiableCredential) {
    // Get the expanded types
    const expandedTypes: SingleOrArray<string> = (
      await jsonld.expand(JsonTransformer.toJSON(credential), {
        documentLoader: this.w3cCredentialsModuleConfig.documentLoader(agentContext),
      })
    )[0]['@type']

    return asArray(expandedTypes)
  }

  private async getPublicKeyFromVerificationMethod(
    agentContext: AgentContext,
    verificationMethod: string
  ): Promise<Key> {
    const documentLoader = this.w3cCredentialsModuleConfig.documentLoader(agentContext)
    const verificationMethodObject = await documentLoader(verificationMethod)
    const verificationMethodClass = JsonTransformer.fromJSON(verificationMethodObject.document, VerificationMethod)

    const key = getKeyFromVerificationMethod(verificationMethodClass)
    return key
  }

  private getSignatureSuitesForCredential(agentContext: AgentContext, credential: W3cJsonLdVerifiableCredential) {
    const WalletKeyPair = createWalletKeyPairClass(agentContext.wallet)

    let proofs = credential.proof

    if (!Array.isArray(proofs)) {
      proofs = [proofs]
    }

    return proofs.map((proof) => {
      const SuiteClass = this.signatureSuiteRegistry.getByProofType(proof.type)?.suiteClass
      if (SuiteClass) {
        return new SuiteClass({
          LDKeyClass: WalletKeyPair,
          proof: {
            verificationMethod: proof.verificationMethod,
          },
          date: proof.created,
          useNativeCanonize: false,
        })
      }
    })
  }
}
