import { JsonTransformer } from '../../../../utils/JsonTransformer'
import { FeatureRegistry } from '../../FeatureRegistry'
import { GoalCode, Feature, Protocol } from '../../models'

describe('Feature Registry', () => {
  test('register goal codes', () => {
    const featureRegistry = new FeatureRegistry()

    const goalCode = new GoalCode({ id: 'aries.vc.issue' })

    expect(JsonTransformer.toJSON(goalCode)).toMatchObject({ id: 'aries.vc.issue', 'feature-type': 'goal-code' })

    featureRegistry.register(goalCode)
    const found = featureRegistry.query({ featureType: GoalCode.type, match: 'aries.*' })

    expect(found.map((t) => t.toJSON())).toStrictEqual([{ id: 'aries.vc.issue', 'feature-type': 'goal-code' }])
  })

  test('register generic feature', () => {
    const featureRegistry = new FeatureRegistry()

    class GenericFeature extends Feature {
      public customFieldString: string
      public customFieldNumber: number
      public constructor(id: string, customFieldString: string, customFieldNumber: number) {
        super({ id, type: 'generic' })
        this.customFieldString = customFieldString
        this.customFieldNumber = customFieldNumber
      }
    }
    featureRegistry.register(new GenericFeature('myId', 'myString', 42))
    const found = featureRegistry.query({ featureType: 'generic', match: '*' })

    expect(found.map((t) => t.toJSON())).toStrictEqual([
      { id: 'myId', 'feature-type': 'generic', customFieldString: 'myString', customFieldNumber: 42 },
    ])
  })

  test('register combined features', () => {
    const featureRegistry = new FeatureRegistry()

    featureRegistry.register(
      new Protocol({ id: 'https://didcomm.org/dummy/1.0', roles: ['requester'] }),
      new Protocol({ id: 'https://didcomm.org/dummy/1.0', roles: ['responder'] }),
      new Protocol({ id: 'https://didcomm.org/dummy/1.0', roles: ['responder'] })
    )
    const found = featureRegistry.query({ featureType: Protocol.type, match: 'https://didcomm.org/dummy/1.0' })

    expect(found.map((t) => t.toJSON())).toStrictEqual([
      { id: 'https://didcomm.org/dummy/1.0', 'feature-type': 'protocol', roles: ['requester', 'responder'] },
    ])
  })
})
