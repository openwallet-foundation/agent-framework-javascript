export * from './v2'
export * from './revocation-notification'
import * as CredentialProtocolOptions from './CredentialProtocolOptions'

export { CredentialProtocol } from './CredentialProtocol'
// NOTE: ideally we don't export the BaseCredentialProtocol, but as the V1CredentialProtocol is defined in the
// anoncreds package, we need to export it. We should at some point look at creating a core package which can be used for
// sharing internal types, and when you want to build you own modules, and an agent package, which is the one you use when
// consuming the framework
export { BaseCredentialProtocol } from './BaseCredentialProtocol'
export { CredentialProtocolOptions }
