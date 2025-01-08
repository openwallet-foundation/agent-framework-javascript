import { Optionality } from '@sphereon/pex-models'

import { getInMemoryAgentOptions } from '../../../../tests'
import { Agent } from '../../../agent/Agent'
import { KeyType } from '../../../crypto'
import { X509Service } from '../../x509'
import { Mdoc } from '../Mdoc'
import { MdocDeviceResponse } from '../MdocDeviceResponse'

describe('mdoc device-response test', () => {
  const agent = new Agent(getInMemoryAgentOptions('mdoc-test-agent', {}))
  beforeEach(async () => {
    await agent.initialize()
  })

  test('can limit the disclosure', async () => {
    const holderKey = await agent.context.wallet.createKey({
      keyType: KeyType.P256,
    })
    const issuerKey = await agent.context.wallet.createKey({
      keyType: KeyType.P256,
    })

    const currentDate = new Date()
    currentDate.setDate(currentDate.getDate() - 1)
    const nextDay = new Date(currentDate)
    nextDay.setDate(currentDate.getDate() + 2)

    const selfSignedCertificate = await X509Service.createSelfSignedCertificate(agent.context, {
      key: issuerKey,
      notBefore: currentDate,
      notAfter: nextDay,
      extensions: [],
    })

    const issuerCertificate = selfSignedCertificate.toString('pem')

    const mdoc = await Mdoc.sign(agent.context, {
      docType: 'org.iso.18013.5.1.mDL',
      holderKey: holderKey,
      namespaces: {
        hello: {
          world: 'from-mdoc',
          secret: 'value',
          nicer: 'dicer',
        },
      },
      issuerCertificate,
    })

    const limitedDisclosedPayload = MdocDeviceResponse.limitDisclosureToInputDescriptor({
      mdoc,
      inputDescriptor: {
        id: mdoc.docType,
        format: {
          mso_mdoc: {
            alg: ['ES256'],
          },
        },
        constraints: {
          limit_disclosure: Optionality.Required,
          fields: [
            {
              path: ["$['hello']['world']"],
              intent_to_retain: true,
            },
            {
              path: ["$['hello']['nicer']"],
              intent_to_retain: false,
            },
          ],
        },
      },
    })

    expect(limitedDisclosedPayload).toStrictEqual({
      hello: {
        world: 'from-mdoc',
        nicer: 'dicer',
      },
    })
  })
})
