import { JsonTransformer } from '../../../../core/src/utils/JsonTransformer'

import { L10nDecorator } from './L10nDecorator'

describe('Decorators | L10nDecorator', () => {
  it('should correctly transform Json to L10nDecorator class', () => {
    const locale = 'en'
    const decorator = JsonTransformer.fromJSON({ locale }, L10nDecorator)

    expect(decorator.locale).toBe(locale)
  })

  it('should correctly transform L10nDecorator class to Json', () => {
    const locale = 'nl'

    const decorator = new L10nDecorator({
      locale,
    })

    const json = JsonTransformer.toJSON(decorator)
    const transformed = {
      locale,
    }

    expect(json).toEqual(transformed)
  })
})
