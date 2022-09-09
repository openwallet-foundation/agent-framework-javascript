import { KeyType } from '../../../crypto'
import { DependencyManager } from '../../../plugins/DependencyManager'
import { SignatureSuiteRegistry, SignatureSuiteToken } from '../SignatureSuiteRegistry'
import { W3cCredentialService } from '../W3cCredentialService'
import { W3cVcModule } from '../W3cVcModule'
import { W3cCredentialRepository } from '../repository'
import { Ed25519Signature2018 } from '../signature-suites'
import { BbsBlsSignature2020, BbsBlsSignatureProof2020 } from '../signature-suites/bbs'

jest.mock('../../../plugins/DependencyManager')
const DependencyManagerMock = DependencyManager as jest.Mock<DependencyManager>

const dependencyManager = new DependencyManagerMock()

describe('W3cVcModule', () => {
  test('registers dependencies on the dependency manager', () => {
    new W3cVcModule().register(dependencyManager)

    expect(dependencyManager.registerSingleton).toHaveBeenCalledTimes(3)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(W3cCredentialService)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(W3cCredentialRepository)
    expect(dependencyManager.registerSingleton).toHaveBeenCalledWith(SignatureSuiteRegistry)

    expect(dependencyManager.registerInstance).toHaveBeenCalledTimes(3)
    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(SignatureSuiteToken, {
      suiteClass: Ed25519Signature2018,
      verificationMethodTypes: ['Ed25519VerificationKey2018', 'Ed25519VerificationKey2020'],
      proofType: 'Ed25519Signature2018',
      keyTypes: [KeyType.Ed25519],
    })

    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(SignatureSuiteToken, {
      suiteClass: BbsBlsSignature2020,
      verificationMethodTypes: ['Bls12381G2Key2020'],
      proofType: 'BbsBlsSignature2020',
      keyTypes: [KeyType.Bls12381g2],
    })

    expect(dependencyManager.registerInstance).toHaveBeenCalledWith(SignatureSuiteToken, {
      suiteClass: BbsBlsSignatureProof2020,
      proofType: 'BbsBlsSignatureProof2020',
      verificationMethodTypes: ['Bls12381G2Key2020'],
      keyTypes: [KeyType.Bls12381g2],
    })
  })
})
