import type {
  CreateSchemaOptions,
  CreateCredentialDefinitionOptions,
  CreateCredentialOfferOptions,
  CreateCredentialReturn,
  CreateCredentialOptions,
  CreateCredentialDefinitionReturn,
  CreateRevocationRegistryDefinitionOptions,
  CreateRevocationRegistryDefinitionReturn,
  CreateRevocationStatusListOptions,
} from './AnonCredsIssuerServiceOptions'
import type { AnonCredsCredentialOffer } from '../models/exchange'
import type { AnonCredsRevocationStatusList, AnonCredsSchema } from '../models/registry'
import type { AgentContext } from '@aries-framework/core'

export const AnonCredsIssuerServiceSymbol = Symbol('AnonCredsIssuerService')

export interface AnonCredsIssuerService {
  createSchema(agentContext: AgentContext, options: CreateSchemaOptions): Promise<AnonCredsSchema>

  // This should store the private part of the credential definition as in the indy-sdk
  // we don't have access to the private part of the credential definition
  createCredentialDefinition(
    agentContext: AgentContext,
    options: CreateCredentialDefinitionOptions,
    metadata?: Record<string, unknown>
  ): Promise<CreateCredentialDefinitionReturn>

  createRevocationRegistryDefinition(
    agentContext: AgentContext,
    options: CreateRevocationRegistryDefinitionOptions
  ): Promise<CreateRevocationRegistryDefinitionReturn>

  createRevocationStatusList(
    agentContext: AgentContext,
    options: CreateRevocationStatusListOptions
  ): Promise<AnonCredsRevocationStatusList>

  createCredentialOffer(
    agentContext: AgentContext,
    options: CreateCredentialOfferOptions
  ): Promise<AnonCredsCredentialOffer>

  createCredential(agentContext: AgentContext, options: CreateCredentialOptions): Promise<CreateCredentialReturn>
}
