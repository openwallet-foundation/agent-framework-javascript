import type { Mdoc } from './Mdoc'

export type MdocVerifyOptions = {
  mdoc: Mdoc
  trustedCertificates?: [string, ...string[]]
}
