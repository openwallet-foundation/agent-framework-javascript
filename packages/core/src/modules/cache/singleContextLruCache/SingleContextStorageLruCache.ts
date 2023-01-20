import type { CacheItem } from './CacheRecord'
import type { AgentContext } from '../../../agent/context'
import type { Cache } from '../Cache'

import { LRUMap } from 'lru_map'

import { AriesFrameworkError } from '../../../error'

import { CacheRecord } from './CacheRecord'
import { CacheRepository } from './CacheRepository'

const CONTEXT_STORAGE_LRU_CACHE_ID = 'CONTEXT_STORAGE_LRU_CACHE_ID'

export interface SingleContextStorageLruCacheOptions {
  /** The maximum number of entries allowed in the cache */
  limit: number
}

/**
 * Cache that leverages the storage associated with the agent context to store cache records.
 * It will keep an in-memory cache of the records to avoid hitting the storage on every read request.
 * Therefor this cache is meant to be used with a single instance of the agent.
 *
 * Due to keeping an in-memory copy of the cache, it is also not meant to be used with multiple
 * agent context instances (meaning multi-tenancy), as they will overwrite the in-memory cache.
 *
 * However, this means the cache is not meant for usage with multiple instances.
 */
export class SingleContextStorageLruCache implements Cache {
  private limit: number
  private _cache?: LRUMap<string, CacheItem>
  private _contextCorrelationId?: string

  public constructor({ limit }: SingleContextStorageLruCacheOptions) {
    this.limit = limit
  }

  public async get<CacheValue>(agentContext: AgentContext, key: string) {
    this.assertContextCorrelationId(agentContext)

    const cache = await this.getCache(agentContext)
    this.removeExpiredItems(cache)

    const item = cache.get(key)

    // Does not exist
    if (!item) return null

    // Expired
    if (item.expiresAt && Date.now() > item.expiresAt) {
      cache.delete(key)
      await this.persistCache(agentContext)
      return null
    }

    return item.value as CacheValue
  }

  public async set<CacheValue>(
    agentContext: AgentContext,
    key: string,
    value: CacheValue,
    expiresInSeconds?: number
  ): Promise<void> {
    this.assertContextCorrelationId(agentContext)

    let expiresDate = undefined

    if (expiresInSeconds) {
      expiresDate = new Date()
      expiresDate.setSeconds(expiresDate.getSeconds() + expiresInSeconds)
    }

    const cache = await this.getCache(agentContext)
    this.removeExpiredItems(cache)

    cache.set(key, {
      expiresAt: expiresDate?.getTime(),
      value,
    })
    await this.persistCache(agentContext)
  }

  public async remove(agentContext: AgentContext, key: string): Promise<void> {
    this.assertContextCorrelationId(agentContext)

    const cache = await this.getCache(agentContext)
    this.removeExpiredItems(cache)
    cache.delete(key)

    await this.persistCache(agentContext)
  }

  private async getCache(agentContext: AgentContext) {
    if (!this._cache) {
      const cacheRecord = await this.fetchCacheRecord(agentContext)
      this._cache = this.lruFromRecord(cacheRecord)
    }

    return this._cache
  }

  private lruFromRecord(cacheRecord: CacheRecord) {
    return new LRUMap<string, CacheItem>(
      this.limit,
      cacheRecord.entries.map((e) => [e.key, e.item])
    )
  }

  private async fetchCacheRecord(agentContext: AgentContext) {
    const cacheRepository = agentContext.dependencyManager.resolve(CacheRepository)
    let cacheRecord = await cacheRepository.findById(agentContext, CONTEXT_STORAGE_LRU_CACHE_ID)

    if (!cacheRecord) {
      cacheRecord = new CacheRecord({
        id: CONTEXT_STORAGE_LRU_CACHE_ID,
        entries: [],
      })

      await cacheRepository.save(agentContext, cacheRecord)
    }

    return cacheRecord
  }

  private removeExpiredItems(cache: LRUMap<string, CacheItem>) {
    cache.forEach((value, key) => {
      if (value.expiresAt && Date.now() > value.expiresAt) {
        cache.delete(key)
      }
    })
  }

  private async persistCache(agentContext: AgentContext) {
    const cacheRepository = agentContext.dependencyManager.resolve(CacheRepository)
    const cache = await this.getCache(agentContext)

    await cacheRepository.update(
      agentContext,
      new CacheRecord({
        entries: cache.toJSON().map(({ key, value: item }) => ({ key, item })),
        id: CONTEXT_STORAGE_LRU_CACHE_ID,
      })
    )
  }

  /**
   * Asserts this class is not used with multiple agent context instances.
   */
  private assertContextCorrelationId(agentContext: AgentContext) {
    if (!this._contextCorrelationId) {
      this._contextCorrelationId = agentContext.contextCorrelationId
    }

    if (this._contextCorrelationId !== agentContext.contextCorrelationId) {
      throw new AriesFrameworkError(
        'SingleContextStorageLruCache can not be used with multiple agent context instances. Register a custom cache implementation in the CacheModule.'
      )
    }
  }
}
