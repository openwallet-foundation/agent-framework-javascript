import type { AnonCredsRequestedAttributeMatch, AnonCredsRequestedPredicateMatch } from '../models'

/**
 * Sort requested attributes and predicates by `revoked` status. The order is:
 *  - first credentials with `revoked` set to undefined, this means no revocation status is needed for the credentials
 *  - then credentials with `revoked` set to false, this means the credentials are not revoked
 *  - then credentials with `revoked` set to true, this means the credentials are revoked
 */
export function sortRequestedCredentialsMatches<
  Requested extends Array<AnonCredsRequestedAttributeMatch> | Array<AnonCredsRequestedPredicateMatch>
>(credentials: Requested) {
  const credentialGoUp = -1
  const credentialGoDown = 1

  // Clone as sort is in place
  const credentialsClone = [...credentials]

  return credentialsClone.sort((credential, compareTo) => {
    // Nothing needs to happen if values are the same
    if (credential.revoked === compareTo.revoked)
      return compareTo.credentialInfo.updatedAt.getTime() - credential.credentialInfo.updatedAt.getTime()

    // Undefined always is at the top
    if (credential.revoked === undefined) return credentialGoUp
    if (compareTo.revoked === undefined) return credentialGoDown

    // Then revoked
    if (credential.revoked === false) return credentialGoUp

    // It means that compareTo is false and credential is true
    return credentialGoDown
  })
}
