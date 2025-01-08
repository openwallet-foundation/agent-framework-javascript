import type { ProofProtocol } from '../protocol/ProofProtocol'

import { ProofsModuleConfig } from '../ProofsModuleConfig'
import { AutoAcceptProof } from '../models'

describe('ProofsModuleConfig', () => {
  test('sets default values', () => {
    const config = new ProofsModuleConfig({
      proofProtocols: [],
    })

    expect(config.autoAcceptProofs).toBe(AutoAcceptProof.Never)
    expect(config.proofProtocols).toEqual([])
  })

  test('sets values', () => {
    const proofProtocol = jest.fn() as unknown as ProofProtocol
    const config = new ProofsModuleConfig({
      autoAcceptProofs: AutoAcceptProof.Always,
      proofProtocols: [proofProtocol],
    })

    expect(config.autoAcceptProofs).toBe(AutoAcceptProof.Always)
    expect(config.proofProtocols).toEqual([proofProtocol])
  })
})
