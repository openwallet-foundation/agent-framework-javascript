import type { AnonCredsCredentialDefinition, AnonCredsSchema } from '../../../../../anoncreds/src'
import type { CredDef, Schema } from 'indy-sdk'

import {
  anonCredsCredentialDefinitionFromIndySdk,
  anonCredsSchemaFromIndySdk,
  indySdkCredentialDefinitionFromAnonCreds,
  indySdkSchemaFromAnonCreds,
} from '../transform'

describe('transform', () => {
  it('anonCredsSchemaFromIndySdk should return a valid anoncreds schema', () => {
    const schema: Schema = {
      attrNames: ['hello'],
      id: '12345:2:Example Schema:1.0.0',
      name: 'Example Schema',
      seqNo: 150,
      ver: '1.0',
      version: '1.0.0',
    }

    expect(anonCredsSchemaFromIndySdk(schema)).toEqual({
      attrNames: ['hello'],
      issuerId: '12345',
      name: 'Example Schema',
      version: '1.0.0',
    })
  })

  it('indySdkSchemaFromAnonCreds should return a valid indy sdk schema', () => {
    const schemaId = '12345:2:Example Schema:1.0.0'
    const schema: AnonCredsSchema = {
      attrNames: ['hello'],
      issuerId: '12345',
      name: 'Example Schema',
      version: '1.0.0',
    }

    expect(indySdkSchemaFromAnonCreds(schemaId, schema, 150)).toEqual({
      attrNames: ['hello'],
      id: '12345:2:Example Schema:1.0.0',
      name: 'Example Schema',
      seqNo: 150,
      ver: '1.0',
      version: '1.0.0',
    })
  })

  it('anonCredsCredentialDefinitionFromIndySdk should return a valid anoncreds credential definition', () => {
    const credDef: CredDef = {
      id: '12345:3:CL:420:someTag',
      schemaId: '8910:2:Example Schema:1.0.0',
      tag: 'someTag',
      type: 'CL',
      value: {
        primary: {
          something: 'string',
        },
      },
      ver: '1.0',
    }

    expect(anonCredsCredentialDefinitionFromIndySdk(credDef)).toEqual({
      issuerId: '12345',
      schemaId: '8910:2:Example Schema:1.0.0',
      tag: 'someTag',
      type: 'CL',
      value: {
        primary: {
          something: 'string',
        },
      },
    })
  })

  it('indySdkCredentialDefinitionFromAnonCreds should return a valid indy sdk credential definition', () => {
    const credentialDefinitionId = '12345:3:CL:420:someTag'
    const credentialDefinition: AnonCredsCredentialDefinition = {
      issuerId: '12345',
      schemaId: '8910:2:Example Schema:1.0.0',
      tag: 'someTag',
      type: 'CL',
      value: {
        primary: {
          something: 'string',
        },
      },
    }

    expect(indySdkCredentialDefinitionFromAnonCreds(credentialDefinitionId, credentialDefinition)).toEqual({
      id: '12345:3:CL:420:someTag',
      schemaId: '8910:2:Example Schema:1.0.0',
      tag: 'someTag',
      type: 'CL',
      value: {
        primary: {
          something: 'string',
        },
      },
      ver: '1.0',
    })
  })

  // TODO: add tests for these models once finalized in the anoncreds spec
  test.todo(
    'anonCredsRevocationRegistryDefinitionFromIndySdk should return a valid anoncreds revocation registry definition'
  )
  test.todo(
    'indySdkRevocationRegistryDefinitionFromAnonCreds should return a valid indy sdk revocation registry definition'
  )
  test.todo('anonCredsRevocationListFromIndySdk should return a valid anoncreds revocation list')
  test.todo('indySdkRevocationRegistryFromAnonCreds should return a valid indy sdk revocation registry')
  test.todo('indySdkRevocationDeltaFromAnonCreds should return a valid indy sdk revocation delta')
})
