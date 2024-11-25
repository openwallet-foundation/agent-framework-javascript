import type { SingleOrArray } from '../../../utils'
import type { W3cJsonLdVerifiableCredential, W3cJwtVerifiableCredential } from '../../vc'
import type {
  DifPresentationExchangeDefinition,
  DifPresentationExchangeSubmission,
  VerifiablePresentation,
} from '../models'

import { JSONPath } from '@astronautlabs/jsonpath'

import { CredoError } from '../../../error'
import { MdocDeviceResponse } from '../../mdoc'
import { ClaimFormat, W3cJsonLdVerifiablePresentation, W3cJwtVerifiablePresentation } from '../../vc'

export type DifPexPresentationWithDescriptor = ReturnType<
  typeof extractPresentationsWithDescriptorsFromSubmission
>[number]
export function extractPresentationsWithDescriptorsFromSubmission(
  presentations: SingleOrArray<VerifiablePresentation>,
  submission: DifPresentationExchangeSubmission,
  definition: DifPresentationExchangeDefinition
) {
  return submission.descriptor_map.map((descriptor) => {
    const [presentation] = JSONPath.query(presentations, descriptor.path) as [VerifiablePresentation | undefined]
    const inputDescriptor = definition.input_descriptors.find(({ id }) => id === descriptor.id)

    if (!presentation) {
      throw new CredoError(
        `Unable to extract presentation at path '${descriptor.path}' for submission descriptor '${descriptor.id}'`
      )
    }

    if (!inputDescriptor) {
      throw new Error(
        `Unable to extract input descriptor '${descriptor.id}' from definition '${definition.id}' for submission '${submission.id}'`
      )
    }

    if (presentation instanceof MdocDeviceResponse) {
      const document = presentation.documents.find((document) => document.docType === descriptor.id)
      if (!document) {
        throw new Error(
          `Unable to extract mdoc document with doctype '${descriptor.id}' from mdoc device response for submission '${submission.id}'.`
        )
      }

      return {
        format: ClaimFormat.MsoMdoc,
        descriptor,
        presentation,
        credential: document,
        inputDescriptor,
      } as const
    } else if (
      presentation instanceof W3cJwtVerifiablePresentation ||
      presentation instanceof W3cJsonLdVerifiablePresentation
    ) {
      if (!descriptor.path_nested) {
        throw new Error(
          `Submission descriptor '${descriptor.id}' for submission '${submission.id}' has no 'path_nested' but presentation is format '${presentation.claimFormat}'`
        )
      }

      const [verifiableCredential] = JSONPath.query(
        // Path is `$.vp.verifiableCredential[]` in case of jwt vp
        presentation.claimFormat === ClaimFormat.JwtVp ? { vp: presentation } : presentation,
        descriptor.path_nested.path
      ) as [W3cJwtVerifiableCredential | W3cJsonLdVerifiableCredential | undefined]

      if (!verifiableCredential) {
        throw new CredoError(
          `Unable to extract credential at path '${descriptor.path_nested.path}' from presentation at path '${descriptor.path}' for submission descriptor '${descriptor.id}'`
        )
      }

      return {
        format: presentation.claimFormat,
        descriptor,
        presentation,
        credential: verifiableCredential,
        inputDescriptor,
      } as const
    } else {
      return {
        format: ClaimFormat.SdJwtVc,
        descriptor,
        presentation,
        credential: presentation,
        inputDescriptor,
      } as const
    }
  })
}
