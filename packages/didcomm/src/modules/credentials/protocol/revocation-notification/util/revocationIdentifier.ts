// indyRevocationIdentifier = <revocation_registry_id>::<credential_revocation_id>

// ThreadID = indy::<revocation_registry_id>::<credential_revocation_id>
export const v1ThreadRegex =
  /(indy)::((?:[\dA-z]{21,22}):4:(?:[\dA-z]{21,22}):3:[Cc][Ll]:(?:(?:[1-9][0-9]*)|(?:[\dA-z]{21,22}:2:.+:[0-9.]+)):.+?:CL_ACCUM:(?:[\dA-z-]+))::(\d+)$/

// CredentialID = <revocation_registry_id>::<credential_revocation_id>
export const v2IndyRevocationIdentifierRegex =
  /((?:[\dA-z]{21,22}):4:(?:[\dA-z]{21,22}):3:[Cc][Ll]:(?:(?:[1-9][0-9]*)|(?:[\dA-z]{21,22}:2:.+:[0-9.]+)):.+?:CL_ACCUM:(?:[\dA-z-]+))::(\d+)$/

export const v2IndyRevocationFormat = 'indy-anoncreds'

// CredentialID = <revocation_registry_id>::<credential_revocation_id>
export const v2AnonCredsRevocationIdentifierRegex = /([a-zA-Z0-9+\-.]+:.+)::(\d+)$/

export const v2AnonCredsRevocationFormat = 'anoncreds'
