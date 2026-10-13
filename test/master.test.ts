import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { expect, test } from 'vitest'
import { deriveChildMnemonic } from '../src/master.js'

test('a child phrase does not derive its sibling', () => {
  const master = generateMnemonic(wordlist, 128)
  const first = deriveChildMnemonic(master, 0)
  const second = deriveChildMnemonic(master, 1)
  expect(first).not.toBe(second)
  expect(deriveChildMnemonic(first, 1)).not.toBe(second)
  expect(deriveChildMnemonic(second, 0)).not.toBe(first)
})
