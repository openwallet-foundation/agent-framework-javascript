import type { LinkedDataProofOptions } from '../LinkedDataProof'
import type { W3cCredentialOptions } from './W3cCredential'

import { instanceToPlain, plainToInstance, Transform, TransformationType } from 'class-transformer'

import { SingleOrArray } from '../../../../utils/type'
import { IsInstanceOrArrayOfInstances } from '../../../../utils/validators'
import { LinkedDataProof, LinkedDataProofTransformer } from '../LinkedDataProof'

import { W3cCredential } from './W3cCredential'

export interface W3cVerifiableCredentialOptions extends W3cCredentialOptions {
  proof: SingleOrArray<LinkedDataProofOptions>
}

export class W3cVerifiableCredential extends W3cCredential {
  public constructor(options: W3cVerifiableCredentialOptions) {
    super(options)
    if (options) {
      this.proof = Array.isArray(options.proof)
        ? options.proof.map((proof) => new LinkedDataProof(proof))
        : new LinkedDataProof(options.proof)
    }
  }

  @LinkedDataProofTransformer()
  @IsInstanceOrArrayOfInstances({ classType: LinkedDataProof })
  public proof!: SingleOrArray<LinkedDataProof>
}

// Custom transformers

export function VerifiableCredentialTransformer() {
  return Transform(
    ({ value, type }: { value: SingleOrArray<W3cVerifiableCredentialOptions>; type: TransformationType }) => {
      if (type === TransformationType.PLAIN_TO_CLASS) {
        if (Array.isArray(value)) return value.map((v) => plainToInstance(W3cVerifiableCredential, v))
        return plainToInstance(W3cVerifiableCredential, value)
      } else if (type === TransformationType.CLASS_TO_PLAIN) {
        if (Array.isArray(value)) return value.map((v) => instanceToPlain(v))
        return instanceToPlain(value)
      }
      // PLAIN_TO_PLAIN
      return value
    }
  )
}
