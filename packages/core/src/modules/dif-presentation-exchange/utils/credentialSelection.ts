import type {
  DifPexCredentialsForRequest,
  DifPexCredentialsForRequestRequirement,
  DifPexCredentialsForRequestSubmissionEntry,
  SubmissionEntryCredential,
} from '../models'
import type { IPresentationDefinition, SelectResults, SubmissionRequirementMatch, PEX } from '@animo-id/pex'
import type {
  SubmissionRequirementMatchFrom,
  SubmissionRequirementMatchInputDescriptor,
} from '@animo-id/pex/dist/main/lib/evaluation/core'
import type { InputDescriptorV1, InputDescriptorV2, SubmissionRequirement } from '@sphereon/pex-models'

import { Status } from '@animo-id/pex'
import { SubmissionRequirementMatchType } from '@animo-id/pex/dist/main/lib/evaluation/core'
import { JSONPath } from '@astronautlabs/jsonpath'
import { decodeSdJwtSync, getClaimsSync } from '@sd-jwt/decode'
import { Rules } from '@sphereon/pex-models'

import { Hasher } from '../../../crypto'
import { CredoError } from '../../../error'
import { MdocRecord } from '../../mdoc'
import { Mdoc } from '../../mdoc/Mdoc'
import { MdocDeviceResponse } from '../../mdoc/MdocDeviceResponse'
import { SdJwtVcRecord } from '../../sd-jwt-vc'
import { ClaimFormat, W3cCredentialRecord } from '../../vc'
import { DifPresentationExchangeError } from '../DifPresentationExchangeError'

import { getSphereonOriginalVerifiableCredential } from './transform'

export async function getCredentialsForRequest(
  // PEX instance with hasher defined
  pex: PEX,
  presentationDefinition: IPresentationDefinition,
  credentialRecords: Array<W3cCredentialRecord | SdJwtVcRecord | MdocRecord>
): Promise<DifPexCredentialsForRequest> {
  const encodedCredentials = credentialRecords.map(getSphereonOriginalVerifiableCredential)
  const selectResultsRaw = pex.selectFrom(presentationDefinition, encodedCredentials)

  const selectResults: CredentialRecordSelectResults = {
    ...selectResultsRaw,
    matches: selectResultsRaw.matches ?? [],
    // Map the encoded credential to their respective credential record
    verifiableCredential:
      selectResultsRaw.verifiableCredential?.map((selectedEncoded, index): SubmissionEntryCredential => {
        const credentialRecordIndex = selectResultsRaw.vcIndexes?.[index]
        if (credentialRecordIndex === undefined || credentialRecordIndex === -1) {
          throw new DifPresentationExchangeError('Unable to find credential in credential records.')
        }
        const credentialRecord = credentialRecords[credentialRecordIndex]
        if (credentialRecord instanceof SdJwtVcRecord) {
          // selectedEncoded always string when SdJwtVcRecord
          // Get the decoded payload from the the selected credential, this already has SD applied
          const { jwt, disclosures } = decodeSdJwtSync(selectedEncoded as string, Hasher.hash)
          const prettyClaims = getClaimsSync(jwt.payload, disclosures, Hasher.hash)

          return {
            type: ClaimFormat.SdJwtVc,
            credentialRecord,
            disclosedPayload: prettyClaims as Record<string, unknown>,
          }
        } else if (credentialRecord instanceof MdocRecord) {
          return {
            type: ClaimFormat.MsoMdoc,
            credentialRecord,
            disclosedPayload: {},
          }
        } else if (credentialRecord instanceof W3cCredentialRecord) {
          return {
            type: credentialRecord.credential.claimFormat,
            credentialRecord,
          }
        } else {
          throw new CredoError(`Unrecognized credential record type`)
        }
      }) ?? [],
  }

  const presentationSubmission: DifPexCredentialsForRequest = {
    requirements: [],
    areRequirementsSatisfied: false,
    name: presentationDefinition.name,
    purpose: presentationDefinition.purpose,
  }

  // If there's no submission requirements, ALL input descriptors MUST be satisfied
  if (!presentationDefinition.submission_requirements || presentationDefinition.submission_requirements.length === 0) {
    presentationSubmission.requirements = getSubmissionRequirementsForAllInputDescriptors(
      presentationDefinition.input_descriptors,
      selectResults
    )
  } else {
    presentationSubmission.requirements = getSubmissionRequirements(presentationDefinition, selectResults)
  }

  const allEntries = presentationSubmission.requirements.flatMap((requirement) => requirement.submissionEntry)

  const inputDescriptorsForMdocCredential = new Map<SubmissionEntryCredential, Set<string>>()
  for (const entry of allEntries)
    for (const verifiableCredential of entry.verifiableCredentials) {
      if (verifiableCredential.type !== ClaimFormat.MsoMdoc) continue

      const set = inputDescriptorsForMdocCredential.get(verifiableCredential) ?? new Set()
      set.add(entry.inputDescriptorId)
      inputDescriptorsForMdocCredential.set(verifiableCredential, set)
    }

  // NOTE: it might be better to apply disclosure per credential/match (as that's also how mdoc does this)
  // however this doesn't work very well in wallets, as you usually won't show the same credential twice with
  // different disclosed attributes
  // Apply limit disclosure for all mdocs
  for (const [verifiableCredential, inputDescriptorIds] of inputDescriptorsForMdocCredential.entries()) {
    if (verifiableCredential.type !== ClaimFormat.MsoMdoc) continue

    const inputDescriptorsForCredential = presentationDefinition.input_descriptors.filter(({ id }) =>
      inputDescriptorIds.has(id)
    )

    const mdoc = Mdoc.fromBase64Url(verifiableCredential.credentialRecord.base64Url)
    verifiableCredential.disclosedPayload = MdocDeviceResponse.limitDisclosureToInputDescriptor({
      inputDescriptor: {
        id: mdoc.docType,
        format: {
          mso_mdoc: {
            alg: [],
          },
        },
        constraints: {
          limit_disclosure: 'required',
          fields: inputDescriptorsForCredential.flatMap((i) => i.constraints?.fields ?? []),
        },
      },
      mdoc: Mdoc.fromBase64Url(verifiableCredential.credentialRecord.base64Url),
    })
  }

  // There may be no requirements if we filter out all optional ones. To not makes things too complicated, we see it as an error
  // for now if a request is made that has no required requirements (but only e.g. min: 0, which means we don't need to disclose anything)
  // I see this more as the fault of the presentation definition, as it should have at least some requirements.
  if (presentationSubmission.requirements.length === 0) {
    throw new DifPresentationExchangeError(
      'Presentation Definition does not require any credentials. Optional credentials are not included in the presentation submission.'
    )
  }

  if (selectResults.areRequiredCredentialsPresent === Status.ERROR) {
    return presentationSubmission
  }

  return {
    ...presentationSubmission,

    // If all requirements are satisfied, the presentation submission is satisfied
    areRequirementsSatisfied: presentationSubmission.requirements.every(
      (requirement) => requirement.isRequirementSatisfied
    ),
  }
}

function getSubmissionRequirements(
  presentationDefinition: IPresentationDefinition,
  selectResults: CredentialRecordSelectResults
): Array<DifPexCredentialsForRequestRequirement> {
  const submissionRequirements: Array<DifPexCredentialsForRequestRequirement> = []

  const matches = selectResults.matches as SubmissionRequirementMatchFrom[]
  if (!matches.every((match) => match.type === SubmissionRequirementMatchType.SubmissionRequirement && match.from)) {
    throw new DifPresentationExchangeError(
      `Expected all matches to be of type '${SubmissionRequirementMatchType.SubmissionRequirement}' with 'from' key.`
    )
  }

  // There are submission requirements, so we need to select the input_descriptors
  // based on the submission requirements
  presentationDefinition.submission_requirements?.forEach((submissionRequirement, submissionRequirementIndex) => {
    // Check: if the submissionRequirement uses `from_nested`, as we don't support this yet
    if (submissionRequirement.from_nested) {
      throw new DifPresentationExchangeError(
        "Presentation definition contains requirement using 'from_nested', which is not supported yet."
      )
    }

    // Check if there's a 'from'. If not the structure is not as we expect it
    if (!submissionRequirement.from) {
      throw new DifPresentationExchangeError("Missing 'from' in submission requirement match")
    }

    const match = matches.find((match) => match.id === submissionRequirementIndex)
    if (!match) {
      throw new Error(`Unable to find a match for submission requirement with index '${submissionRequirementIndex}'`)
    }

    if (submissionRequirement.rule === Rules.All) {
      const selectedSubmission = getSubmissionRequirementRuleAll(
        submissionRequirement,
        presentationDefinition,
        selectResults.verifiableCredential,
        match
      )
      submissionRequirements.push(selectedSubmission)
    } else {
      const selectedSubmission = getSubmissionRequirementRulePick(
        submissionRequirement,
        presentationDefinition,
        selectResults.verifiableCredential,
        match
      )

      submissionRequirements.push(selectedSubmission)
    }
  })

  // Submission may have requirement that doesn't require a credential to be submitted (e.g. min: 0)
  // We use minimization strategy, and thus only disclose the minimum amount of information
  const requirementsWithCredentials = submissionRequirements.filter((requirement) => requirement.needsCount > 0)

  return requirementsWithCredentials
}

function getSubmissionRequirementsForAllInputDescriptors(
  inputDescriptors: Array<InputDescriptorV1> | Array<InputDescriptorV2>,
  selectResults: CredentialRecordSelectResults
): Array<DifPexCredentialsForRequestRequirement> {
  const submissionRequirements: Array<DifPexCredentialsForRequestRequirement> = []

  const matches = selectResults.matches as SubmissionRequirementMatchInputDescriptor[]
  if (!matches.every((match) => match.type === SubmissionRequirementMatchType.InputDescriptor)) {
    throw new DifPresentationExchangeError(
      `Expected all matches to be of type '${SubmissionRequirementMatchType.InputDescriptor}' when.`
    )
  }

  for (const inputDescriptor of inputDescriptors) {
    const submission = getSubmissionForInputDescriptor(inputDescriptor, selectResults.verifiableCredential, matches)
    submissionRequirements.push({
      rule: Rules.Pick,
      needsCount: 1, // Every input descriptor is a distinct requirement, so the count is always 1,
      submissionEntry: [submission],
      isRequirementSatisfied: submission.verifiableCredentials.length >= 1,
    })
  }

  return submissionRequirements
}

function getSubmissionRequirementRuleAll(
  submissionRequirement: SubmissionRequirement,
  presentationDefinition: IPresentationDefinition,
  verifiableCredentials: SubmissionEntryCredential[],
  match: SubmissionRequirementMatchFrom
) {
  // Check if there's a 'from'. If not the structure is not as we expect it
  if (!submissionRequirement.from)
    throw new DifPresentationExchangeError("Missing 'from' in submission requirement match.")

  const selectedSubmission: DifPexCredentialsForRequestRequirement = {
    rule: Rules.All,
    needsCount: 0,
    name: submissionRequirement.name,
    purpose: submissionRequirement.purpose,
    submissionEntry: [],
    isRequirementSatisfied: false,
  }

  for (const inputDescriptor of presentationDefinition.input_descriptors) {
    // We only want to get the submission if the input descriptor belongs to the group
    if (!inputDescriptor.group?.includes(match.from)) continue

    const submission = getSubmissionForInputDescriptor(inputDescriptor, verifiableCredentials, match.input_descriptors)

    // Rule ALL, so for every input descriptor that matches in this group, we need to add it
    selectedSubmission.needsCount += 1
    selectedSubmission.submissionEntry.push(submission)
  }

  return {
    ...selectedSubmission,

    // If all submissions have a credential, the requirement is satisfied
    isRequirementSatisfied: selectedSubmission.submissionEntry.every(
      (submission) => submission.verifiableCredentials.length >= 1
    ),
  }
}

function getSubmissionRequirementRulePick(
  submissionRequirement: SubmissionRequirement,
  presentationDefinition: IPresentationDefinition,
  verifiableCredentials: SubmissionEntryCredential[],
  match: SubmissionRequirementMatchFrom
) {
  // Check if there's a 'from'. If not the structure is not as we expect it
  if (!submissionRequirement.from) {
    throw new DifPresentationExchangeError("Missing 'from' in submission requirement match.")
  }

  const selectedSubmission: DifPexCredentialsForRequestRequirement = {
    rule: Rules.Pick,
    needsCount: submissionRequirement.count ?? submissionRequirement.min ?? 1,
    name: submissionRequirement.name,
    purpose: submissionRequirement.purpose,
    // If there's no count, min, or max we assume one credential is required for submission
    // however, the exact behavior is not specified in the spec
    submissionEntry: [],
    isRequirementSatisfied: false,
  }

  const satisfiedSubmissions: Array<DifPexCredentialsForRequestSubmissionEntry> = []
  const unsatisfiedSubmissions: Array<DifPexCredentialsForRequestSubmissionEntry> = []

  for (const inputDescriptor of presentationDefinition.input_descriptors) {
    // We only want to get the submission if the input descriptor belongs to the group
    if (!inputDescriptor.group?.includes(match.from)) continue

    const submission = getSubmissionForInputDescriptor(inputDescriptor, verifiableCredentials, match.input_descriptors)

    if (submission.verifiableCredentials.length >= 1) {
      satisfiedSubmissions.push(submission)
    } else {
      unsatisfiedSubmissions.push(submission)
    }

    // If we have found enough credentials to satisfy the requirement, we could stop
    // but the user may not want the first x that match, so we continue and return all matches
    // if (satisfiedSubmissions.length === selectedSubmission.needsCount) break
  }

  return {
    ...selectedSubmission,

    // If there are enough satisfied submissions, the requirement is satisfied
    isRequirementSatisfied: satisfiedSubmissions.length >= selectedSubmission.needsCount,

    // if the requirement is satisfied, we only need to return the satisfied submissions
    // however if the requirement is not satisfied, we include all entries so the wallet could
    // render which credentials are missing.
    submissionEntry:
      satisfiedSubmissions.length >= selectedSubmission.needsCount
        ? satisfiedSubmissions
        : [...satisfiedSubmissions, ...unsatisfiedSubmissions],
  }
}

function getSubmissionForInputDescriptor(
  inputDescriptor: InputDescriptorV1 | InputDescriptorV2,
  verifiableCredentials: SubmissionEntryCredential[],
  matches: SubmissionRequirementMatchInputDescriptor[]
): DifPexCredentialsForRequestSubmissionEntry {
  const matchesForInputDescriptor = matches.filter((m) => m.id === inputDescriptor.id)

  const submissionEntry: DifPexCredentialsForRequestSubmissionEntry = {
    inputDescriptorId: inputDescriptor.id,
    name: inputDescriptor.name,
    purpose: inputDescriptor.purpose,
    verifiableCredentials: matchesForInputDescriptor.flatMap((matchForInputDescriptor) =>
      extractCredentialsFromInputDescriptorMatch(matchForInputDescriptor, verifiableCredentials)
    ),
  }

  // return early if no matches.
  if (!matchesForInputDescriptor?.length) return submissionEntry

  return submissionEntry
}

function extractCredentialsFromInputDescriptorMatch(
  match: SubmissionRequirementMatchInputDescriptor,
  availableCredentials: SubmissionEntryCredential[]
) {
  const verifiableCredentials: SubmissionEntryCredential[] = []

  for (const vcPath of match.vc_path) {
    const [verifiableCredential] = JSONPath.query(
      { verifiableCredential: availableCredentials },
      vcPath
    ) as SubmissionEntryCredential[]
    verifiableCredentials.push(verifiableCredential)
  }

  return verifiableCredentials
}

/**
 * Custom SelectResults that includes the Credo records instead of the encoded verifiable credential
 */
type CredentialRecordSelectResults = Omit<SelectResults, 'verifiableCredential'> & {
  verifiableCredential: SubmissionEntryCredential[]
  matches: SubmissionRequirementMatch[]
}
