import type { FeatureQuery, Feature } from './models'

import { injectable } from 'tsyringe'

@injectable()
class FeatureRegistry {
  private features: Feature[] = []

  /**
   * Register a single or set of Features on the registry
   *
   * @param features set of {Feature} objects or any inherited class
   */
  public register(...features: Feature[]) {
    for (const feature of features) {
      const index = this.features.findIndex((item) => item.type === feature.type && item.id === feature.id)

      if (index > -1) {
        this.features[index] = this.features[index].combine(feature)
      } else {
        this.features.push(feature)
      }
    }
  }

  /**
   * Perform a set of queries in the registry, supporting wildcards (*) as
   * expressed in Aries RFC 0557.
   *
   * @see https://github.com/hyperledger/aries-rfcs/blob/560ffd23361f16a01e34ccb7dcc908ec28c5ddb1/features/0557-discover-features-v2/README.md
   *
   * @param queries set of {FeatureQuery} objects to query features
   * @returns array containing all matching features (can be empty)
   */
  public query(...queries: FeatureQuery[]) {
    const output = []
    for (const query of queries) {
      const items = this.features.filter((item) => item.type === query.featureType)
      // An * will return all features of a given type (e.g. all protocols, all goal codes, all AIP configs)
      if (query.match === '*') {
        output.push(...items)
        // An string ending with * will return a family of features of a certain type
        // (e.g. all versions of a given protocol, all subsets of an AIP, etc.)
      } else if (query.match.endsWith('*')) {
        const match = query.match.slice(0, -1)
        output.push(...items.filter((m) => m.id.startsWith(match)))
        // Exact matching (single feature)
      } else {
        output.push(...items.filter((m) => m.id === query.match))
      }
    }
    return output
  }
}

export { FeatureRegistry }
