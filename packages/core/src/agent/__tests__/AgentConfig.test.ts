import { agentDependencies, getAgentConfig } from '../../../tests/helpers'
import { AgentConfig } from '../AgentConfig'

describe('AgentConfig', () => {
  describe('label', () => {
    it('should return new label after setter is called', async () => {
      expect.assertions(2)
      const newLabel = 'Agent: Agent Class Test 2'

      const agentConfig = getAgentConfig(
        'AgentConfig Test',
        {},
        {
          label: 'Test',
        }
      )
      expect(agentConfig.label).toBe('Test')

      agentConfig.label = newLabel
      expect(agentConfig.label).toBe(newLabel)
    })
  })

  describe('extend()', () => {
    it('extends the existing AgentConfig', () => {
      const agentConfig = new AgentConfig(
        {
          label: 'hello',
        },
        agentDependencies
      )

      const newAgentConfig = agentConfig.extend({})

      expect(newAgentConfig).toMatchObject({
        label: 'hello',
      })
    })

    it('takes the init config from the extend method', () => {
      const agentConfig = new AgentConfig(
        {
          label: 'hello',
        },
        agentDependencies
      )

      const newAgentConfig = agentConfig.extend({
        label: 'anotherLabel',
      })

      expect(newAgentConfig).toMatchObject({
        label: 'anotherLabel',
      })
    })
  })
})
