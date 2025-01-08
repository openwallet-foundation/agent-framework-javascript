import type { DiscoverFeaturesService } from './services'
import type { FeatureQueryOptions } from '../../models'

/**
 * Get the supported protocol versions based on the provided discover features services.
 */
export type DiscoverFeaturesProtocolVersionType<DFSs extends DiscoverFeaturesService[]> = DFSs[number]['version']

/**
 * Get the service map for usage in the discover features module. Will return a type mapping of protocol version to service.
 *
 * @example
 * ```
 * type ServiceMap = DiscoverFeaturesServiceMap<[V1DiscoverFeaturesService,V2DiscoverFeaturesService]>
 *
 * // equal to
 * type ServiceMap = {
 *   v1: V1DiscoverFeatureService
 *   v2: V2DiscoverFeaturesService
 * }
 * ```
 */
export type DiscoverFeaturesServiceMap<DFSs extends DiscoverFeaturesService[]> = {
  [DFS in DFSs[number] as DFS['version']]: DiscoverFeaturesService
}

interface BaseOptions {
  connectionId: string
}

export interface QueryFeaturesOptions<DFSs extends DiscoverFeaturesService[] = DiscoverFeaturesService[]>
  extends BaseOptions {
  protocolVersion: DiscoverFeaturesProtocolVersionType<DFSs>
  queries: FeatureQueryOptions[]
  awaitDisclosures?: boolean
  awaitDisclosuresTimeoutMs?: number
  comment?: string
}

export interface DiscloseFeaturesOptions<DFSs extends DiscoverFeaturesService[] = DiscoverFeaturesService[]>
  extends BaseOptions {
  protocolVersion: DiscoverFeaturesProtocolVersionType<DFSs>
  disclosureQueries: FeatureQueryOptions[]
  threadId?: string
}
