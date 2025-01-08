import { isValidJweStructure } from '../JWE'

describe('ValidJWEStructure', () => {
  test('throws error when the response message has an invalid JWE structure', async () => {
    const responseMessage = 'invalid JWE structure'
    expect(isValidJweStructure(responseMessage)).toBe(false)
  })

  test('valid JWE structure', async () => {
    const responseMessage = {
      protected:
        'eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJNYUNKa3B1YzltZWxnblEtUk8teWtsQWRBWWxzY21GdFEzd1hjZ3R0R0dlSmVsZDBEc2pmTUpSWUtYUDA0cTQ2IiwiaGVhZGVyIjp7ImtpZCI6IkJid2ZCaDZ3bWdZUnJ1TlozZXhFelk2RXBLS2g4cGNob211eDJQUjg5bURlIiwiaXYiOiJOWVJGb0xoUG1EZlFhQ3czUzQ2RmM5M1lucWhDUnhKbiIsInNlbmRlciI6IkRIQ0lsdE5tcEgwRlRrd3NuVGNSWXgwZmYzTHBQTlF6VG1jbUdhRW83aGU5d19ERkFmemNTWFdhOEFnNzRHVEpfdnBpNWtzQkQ3MWYwYjI2VF9mVHBfV2FscTBlWUhmeTE4ZEszejhUTkJFQURpZ1VPWi1wR21pV3FrUT0ifX1dfQ==',
      iv: 'KNezOOt7JJtuU2q1',
      ciphertext: 'mwRMpVg9wkF4rIZcBeWLcc0fWhs=',
      tag: '0yW0Lx8-vWevj3if91R06g==',
    }
    expect(isValidJweStructure(responseMessage)).toBe(true)
  })
})
