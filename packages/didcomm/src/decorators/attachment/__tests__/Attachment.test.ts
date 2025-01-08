import * as didJwsz6Mkf from '../../../../../core/src/crypto/__tests__/__fixtures__/didJwsz6Mkf'
import * as didJwsz6Mkv from '../../../../../core/src/crypto/__tests__/__fixtures__/didJwsz6Mkv'
import { JsonEncoder } from '../../../../../core/src/utils/JsonEncoder'
import { JsonTransformer } from '../../../../../core/src/utils/JsonTransformer'
import { Attachment, AttachmentData } from '../Attachment'

const mockJson = {
  '@id': 'ceffce22-6471-43e4-8945-b604091981c9',
  description: 'A small picture of a cat',
  filename: 'cat.png',
  'mime-type': 'text/plain',
  lastmod_time: new Date(),
  byte_count: 9200,
  data: {
    json: {
      hello: 'world!',
    },
    sha256: '00d7b2068a0b237f14a7979bbfc01ad62f60792e459467bfc4a7d3b9a6dbbe3e',
  },
}

const mockJsonBase64 = {
  '@id': 'ceffce22-6471-43e4-8945-b604091981c9',
  description: 'A small picture of a cat',
  filename: 'cat.png',
  'mime-type': 'text/plain',
  lastmod_time: new Date(),
  byte_count: 9200,
  data: {
    base64: JsonEncoder.toBase64(mockJson.data.json),
  },
}

const id = 'ceffce22-6471-43e4-8945-b604091981c9'
const description = 'A small picture of a cat'
const filename = 'cat.png'
const mimeType = 'text/plain'
const lastmodTime = new Date()
const byteCount = 9200
const data = {
  json: {
    hello: 'world!',
  },
  sha256: '00d7b2068a0b237f14a7979bbfc01ad62f60792e459467bfc4a7d3b9a6dbbe3e',
}
const dataInstance = new AttachmentData(data)

describe('Decorators | Attachment', () => {
  it('should correctly transform Json to Attachment class', () => {
    const decorator = JsonTransformer.fromJSON(mockJson, Attachment)

    expect(decorator.id).toBe(mockJson['@id'])
    expect(decorator.description).toBe(mockJson.description)
    expect(decorator.filename).toBe(mockJson.filename)
    expect(decorator.lastmodTime).toEqual(mockJson.lastmod_time)
    expect(decorator.byteCount).toEqual(mockJson.byte_count)
    expect(decorator.data).toMatchObject(mockJson.data)
  })

  it('should correctly transform Attachment class to Json', () => {
    const decorator = new Attachment({
      id,
      description,
      filename,
      mimeType,
      lastmodTime,
      byteCount,
      data: dataInstance,
    })

    const json = JsonTransformer.toJSON(decorator)
    const transformed = {
      '@id': id,
      description,
      filename,
      'mime-type': mimeType,
      lastmod_time: lastmodTime,
      byte_count: byteCount,
      data,
    }

    expect(json).toMatchObject(transformed)
  })

  it('should return the data correctly if only JSON exists', () => {
    const decorator = JsonTransformer.fromJSON(mockJson, Attachment)

    const gotData = decorator.getDataAsJson()
    expect(decorator.data.json).toEqual(gotData)
  })

  it('should return the data correctly if only Base64 exists', () => {
    const decorator = JsonTransformer.fromJSON(mockJsonBase64, Attachment)

    const gotData = decorator.getDataAsJson()
    expect(mockJson.data.json).toEqual(gotData)
  })

  describe('addJws', () => {
    it('correctly adds the jws to the data', async () => {
      const base64 = JsonEncoder.toBase64(didJwsz6Mkf.DATA_JSON)
      const attachment = new Attachment({
        id: 'some-uuid',
        data: new AttachmentData({
          base64,
        }),
      })

      expect(attachment.data.jws).toBeUndefined()

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { payload, ...detachedJws } = didJwsz6Mkf.JWS_JSON
      attachment.addJws(didJwsz6Mkf.JWS_JSON)
      expect(attachment.data.jws).toEqual(detachedJws)

      attachment.addJws(didJwsz6Mkv.JWS_JSON)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { payload: payload2, ...detachedJws2 } = didJwsz6Mkv.JWS_JSON
      expect(attachment.data.jws).toEqual({ signatures: [detachedJws, detachedJws2] })

      expect(JsonTransformer.toJSON(attachment)).toMatchObject({
        '@id': 'some-uuid',
        data: {
          base64: JsonEncoder.toBase64(didJwsz6Mkf.DATA_JSON),
          jws: { signatures: [detachedJws, detachedJws2] },
        },
      })
    })
  })
})
