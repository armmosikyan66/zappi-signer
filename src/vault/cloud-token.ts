import { z } from 'zod'

export interface CloudTokenRecord {
  id: string
  name: string
  potId: string
  publicKey: string
  expiresAt: number
  revoked: boolean
  handoffOnly: boolean
}

export const tokenListSchema = z
  .array(
    z.object({
      id: z.string().min(1).max(80),
      name: z.string().min(1).max(64),
      potId: z.string().min(1).max(80),
      publicKey: z.string().min(1).max(4096),
      expiresAt: z.number(),
      revoked: z.boolean(),
      handoffOnly: z.boolean(),
    }),
  )
  .max(32)
