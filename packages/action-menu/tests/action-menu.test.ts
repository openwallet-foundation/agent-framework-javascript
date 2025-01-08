import type { ConnectionRecord } from '@credo-ts/didcomm'

import { Agent } from '@credo-ts/core'

import { makeConnection, testLogger, setupSubjectTransports, getInMemoryAgentOptions } from '../../core/tests'

import { waitForActionMenuRecord } from './helpers'

import { ActionMenu, ActionMenuModule, ActionMenuRecord, ActionMenuRole, ActionMenuState } from '@credo-ts/action-menu'

const modules = {
  actionMenu: new ActionMenuModule(),
}

const faberAgentOptions = getInMemoryAgentOptions(
  'Faber Action Menu',
  {
    endpoints: ['rxjs:faber'],
  },
  {},
  modules
)

const aliceAgentOptions = getInMemoryAgentOptions(
  'Alice Action Menu',
  {
    endpoints: ['rxjs:alice'],
  },
  {},
  modules
)

describe('Action Menu', () => {
  let faberAgent: Agent<typeof modules>
  let aliceAgent: Agent<typeof modules>
  let faberConnection: ConnectionRecord
  let aliceConnection: ConnectionRecord

  const rootMenu = new ActionMenu({
    title: 'Welcome',
    description: 'This is the root menu',
    options: [
      {
        name: 'option-1',
        description: 'Option 1 description',
        title: 'Option 1',
      },
      {
        name: 'option-2',
        description: 'Option 2 description',
        title: 'Option 2',
      },
    ],
  })

  const submenu1 = new ActionMenu({
    title: 'Menu 1',
    description: 'This is first submenu',
    options: [
      {
        name: 'option-1-1',
        description: '1-1 desc',
        title: '1-1 title',
      },
      {
        name: 'option-1-2',
        description: '1-1 desc',
        title: '1-1 title',
      },
    ],
  })

  beforeEach(async () => {
    faberAgent = new Agent(faberAgentOptions)
    aliceAgent = new Agent(aliceAgentOptions)

    setupSubjectTransports([faberAgent, aliceAgent])

    await faberAgent.initialize()
    await aliceAgent.initialize()
    ;[aliceConnection, faberConnection] = await makeConnection(aliceAgent, faberAgent)
  })

  afterEach(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice requests menu to Faber and selects an option once received', async () => {
    testLogger.test('Alice sends menu request to Faber')
    let aliceActionMenuRecord = await aliceAgent.modules.actionMenu.requestMenu({ connectionId: aliceConnection.id })

    testLogger.test('Faber waits for menu request from Alice')
    await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.PreparingRootMenu,
    })

    testLogger.test('Faber sends root menu to Alice')
    await faberAgent.modules.actionMenu.sendMenu({ connectionId: faberConnection.id, menu: rootMenu })

    testLogger.test('Alice waits until she receives menu')
    aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(rootMenu)
    const faberActiveMenu = await faberAgent.modules.actionMenu.findActiveMenu({
      connectionId: faberConnection.id,
      role: ActionMenuRole.Responder,
    })
    expect(faberActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(faberActiveMenu?.state).toBe(ActionMenuState.AwaitingSelection)

    testLogger.test('Alice selects menu item')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1' },
    })

    testLogger.test('Faber waits for menu selection from Alice')
    await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.Done,
    })

    // As Alice has responded, menu should be closed (done state)
    const aliceActiveMenu = await aliceAgent.modules.actionMenu.findActiveMenu({
      connectionId: aliceConnection.id,
      role: ActionMenuRole.Requester,
    })
    expect(aliceActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(aliceActiveMenu?.state).toBe(ActionMenuState.Done)
  })

  test('Faber sends root menu and Alice selects an option', async () => {
    testLogger.test('Faber sends root menu to Alice')
    await faberAgent.modules.actionMenu.sendMenu({ connectionId: faberConnection.id, menu: rootMenu })

    testLogger.test('Alice waits until she receives menu')
    const aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(rootMenu)
    const faberActiveMenu = await faberAgent.modules.actionMenu.findActiveMenu({
      connectionId: faberConnection.id,
      role: ActionMenuRole.Responder,
    })
    expect(faberActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(faberActiveMenu?.state).toBe(ActionMenuState.AwaitingSelection)

    testLogger.test('Alice selects menu item')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1' },
    })

    testLogger.test('Faber waits for menu selection from Alice')
    await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.Done,
    })

    // As Alice has responded, menu should be closed (done state)
    const aliceActiveMenu = await aliceAgent.modules.actionMenu.findActiveMenu({
      connectionId: aliceConnection.id,
      role: ActionMenuRole.Requester,
    })
    expect(aliceActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(aliceActiveMenu?.state).toBe(ActionMenuState.Done)
  })

  test('Menu navigation', async () => {
    testLogger.test('Faber sends root menu ')
    let faberActionMenuRecord = await faberAgent.modules.actionMenu.sendMenu({
      connectionId: faberConnection.id,
      menu: rootMenu,
    })

    const rootThreadId = faberActionMenuRecord.threadId

    testLogger.test('Alice waits until she receives menu')
    let aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(rootMenu)
    expect(aliceActionMenuRecord.threadId).toEqual(rootThreadId)

    testLogger.test('Alice selects menu item 1')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1' },
    })

    testLogger.test('Faber waits for menu selection from Alice')
    faberActionMenuRecord = await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.Done,
    })

    // As Alice has responded, menu should be closed (done state)
    let aliceActiveMenu = await aliceAgent.modules.actionMenu.findActiveMenu({
      connectionId: aliceConnection.id,
      role: ActionMenuRole.Requester,
    })
    expect(aliceActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(aliceActiveMenu?.state).toBe(ActionMenuState.Done)
    expect(aliceActiveMenu?.threadId).toEqual(rootThreadId)

    testLogger.test('Faber sends submenu to Alice')
    faberActionMenuRecord = await faberAgent.modules.actionMenu.sendMenu({
      connectionId: faberConnection.id,
      menu: submenu1,
    })

    testLogger.test('Alice waits until she receives submenu')
    aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(submenu1)
    expect(aliceActionMenuRecord.threadId).toEqual(rootThreadId)

    testLogger.test('Alice selects menu item 1-1')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1-1' },
    })

    testLogger.test('Faber waits for menu selection from Alice')
    faberActionMenuRecord = await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.Done,
    })

    // As Alice has responded, menu should be closed (done state)
    aliceActiveMenu = await aliceAgent.modules.actionMenu.findActiveMenu({
      connectionId: aliceConnection.id,
      role: ActionMenuRole.Requester,
    })
    expect(aliceActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(aliceActiveMenu?.state).toBe(ActionMenuState.Done)
    expect(aliceActiveMenu?.threadId).toEqual(rootThreadId)

    testLogger.test('Alice sends menu request to Faber')
    aliceActionMenuRecord = await aliceAgent.modules.actionMenu.requestMenu({ connectionId: aliceConnection.id })

    testLogger.test('Faber waits for menu request from Alice')
    faberActionMenuRecord = await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.PreparingRootMenu,
    })

    testLogger.test('This new menu request must have a different thread Id')
    expect(faberActionMenuRecord.menu).toBeUndefined()
    expect(aliceActionMenuRecord.threadId).not.toEqual(rootThreadId)
    expect(faberActionMenuRecord.threadId).toEqual(aliceActionMenuRecord.threadId)
  })

  test('Menu clearing', async () => {
    testLogger.test('Faber sends root menu to Alice')
    await faberAgent.modules.actionMenu.sendMenu({ connectionId: faberConnection.id, menu: rootMenu })

    testLogger.test('Alice waits until she receives menu')
    let aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(rootMenu)
    let faberActiveMenu = await faberAgent.modules.actionMenu.findActiveMenu({
      connectionId: faberConnection.id,
      role: ActionMenuRole.Responder,
    })
    expect(faberActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(faberActiveMenu?.state).toBe(ActionMenuState.AwaitingSelection)

    await faberAgent.modules.actionMenu.clearActiveMenu({
      connectionId: faberConnection.id,
      role: ActionMenuRole.Responder,
    })

    testLogger.test('Alice selects menu item')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1' },
    })

    // Exception

    testLogger.test('Faber rejects selection, as menu has been cleared')
    // Faber sends error report to Alice, meaning that her Menu flow will be cleared
    aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.Null,
      role: ActionMenuRole.Requester,
    })

    testLogger.test('Alice request a new menu')
    await aliceAgent.modules.actionMenu.requestMenu({
      connectionId: aliceConnection.id,
    })

    testLogger.test('Faber waits for menu request from Alice')
    await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.PreparingRootMenu,
    })

    testLogger.test('Faber sends root menu to Alice')
    await faberAgent.modules.actionMenu.sendMenu({ connectionId: faberConnection.id, menu: rootMenu })

    testLogger.test('Alice waits until she receives menu')
    aliceActionMenuRecord = await waitForActionMenuRecord(aliceAgent, {
      state: ActionMenuState.PreparingSelection,
    })

    expect(aliceActionMenuRecord.menu).toEqual(rootMenu)
    faberActiveMenu = await faberAgent.modules.actionMenu.findActiveMenu({
      connectionId: faberConnection.id,
      role: ActionMenuRole.Responder,
    })
    expect(faberActiveMenu).toBeInstanceOf(ActionMenuRecord)
    expect(faberActiveMenu?.state).toBe(ActionMenuState.AwaitingSelection)

    testLogger.test('Alice selects menu item')
    await aliceAgent.modules.actionMenu.performAction({
      connectionId: aliceConnection.id,
      performedAction: { name: 'option-1' },
    })

    testLogger.test('Faber waits for menu selection from Alice')
    await waitForActionMenuRecord(faberAgent, {
      state: ActionMenuState.Done,
    })
  })
})
