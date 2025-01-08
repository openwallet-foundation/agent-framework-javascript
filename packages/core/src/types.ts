import type { Logger } from './logger'

export enum KeyDerivationMethod {
  /** default value in indy-sdk. Will be used when no value is provided */
  Argon2IMod = 'ARGON2I_MOD',
  /** less secure, but faster */
  Argon2IInt = 'ARGON2I_INT',
  /** raw wallet master key */
  Raw = 'RAW',
}

export interface WalletStorageConfig {
  type: string
  [key: string]: unknown
}

export interface WalletConfig {
  id: string
  key: string
  keyDerivationMethod?: KeyDerivationMethod
  storage?: WalletStorageConfig
}

export interface WalletConfigRekey {
  id: string
  key: string
  rekey: string
  keyDerivationMethod?: KeyDerivationMethod
  rekeyDerivationMethod?: KeyDerivationMethod
}

export interface WalletExportImportConfig {
  key: string
  path: string
}

export interface InitConfig {
  /**
   * Agent public endpoints, sorted by priority (higher priority first)
   */
  label: string
  walletConfig?: WalletConfig
  logger?: Logger
  autoUpdateStorageOnStartup?: boolean
  backupBeforeStorageUpdate?: boolean

  /**
   * Allow insecure http urls in places where this is usually required.
   * Unsecure http urls may still be allowed in places where this is not checked (e.g. didcomm)
   *
   * For some flows this config option is set globally, which means that different agent configurations
   * will fight for the configuration. It is meant as a local development option.
   *
   * Use with caution
   *
   * @default false
   */
  allowInsecureHttpUrls?: boolean
}

export type JsonValue = string | number | boolean | null | JsonObject | JsonArray
export type JsonArray = Array<JsonValue>
export interface JsonObject {
  [property: string]: JsonValue
}

/**
 * Flatten an array of arrays
 * @example
 * ```
 * type Flattened = FlatArray<[[1], [2]]>
 *
 * // is the same as
 * type Flattened = 1 | 2
 * ```
 */
export type FlatArray<Arr> = Arr extends ReadonlyArray<infer InnerArr> ? FlatArray<InnerArr> : Arr

/**
 * Get the awaited (resolved promise) type of Promise type.
 */
export type Awaited<T> = T extends Promise<infer U> ? U : never

/**
 * Type util that returns `true` or `false` based on whether the input type `T` is of type `any`
 */
export type IsAny<T> = unknown extends T ? ([keyof T] extends [never] ? false : true) : false

// FIXME: the following types are duplicated in DIDComm module. They were placed here to remove dependency
// to that module
export interface PlaintextMessage {
  '@type': string
  '@id': string
  '~thread'?: {
    thid?: string
    pthid?: string
  }
  [key: string]: unknown
}

export type EncryptedMessage = {
  protected: string
  iv: string
  ciphertext: string
  tag: string
}
