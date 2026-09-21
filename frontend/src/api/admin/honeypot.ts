/**
 * Admin Honeypot API endpoints
 * 蜜罐 Key 管理：创建 / 列表 / 更新 / 转换泄露 Key / 命中事件查询
 */

import { apiClient } from '../client'

export interface HoneypotConfig {
  mode: 'synthetic' | 'relay' | string
  payload_variant?: string
  custom_payload?: string
  relay_endpoint?: string
  relay_api_key?: string
  relay_model?: string
  marker?: string
}

export interface HoneypotKeyItem {
  id: number
  name: string
  key_masked: string
  status: string
  config: HoneypotConfig | null
  event_count: number
  last_event_at: string | null
  created_at: string
  owner_email?: string
  owner_name?: string
}

export interface HoneypotEventItem {
  id: number
  api_key_id: number
  source: 'gateway' | 'oob' | string
  method: string
  path: string
  client_ip: string
  user_agent?: string
  model: string
  is_stream: boolean
  body?: string
  body_truncated: boolean
  intel?: {
    env_report?: string
    env_report_analysis?: Record<string, string>
    emails_in_prompt?: string[]
    oob_hit?: boolean
    marker?: string
  }
  injected_payload?: string
  response_mode: string
  created_at: string
}

export interface HoneypotEventListResult {
  items: HoneypotEventItem[]
  total: number
  page: number
  page_size: number
}

export interface CreateHoneypotKeyPayload {
  name: string
  config: HoneypotConfig
}

export interface ConvertHoneypotKeyPayload {
  key_id: number
  config: HoneypotConfig
  issue_replacement: boolean
}

function normalizeConfig(config: HoneypotConfig): HoneypotConfig {
  const out: HoneypotConfig = { mode: config.mode || 'synthetic' }
  if (config.payload_variant) out.payload_variant = config.payload_variant
  if (config.custom_payload) out.custom_payload = config.custom_payload
  if (config.relay_endpoint) out.relay_endpoint = config.relay_endpoint
  if (config.relay_api_key) out.relay_api_key = config.relay_api_key
  if (config.relay_model) out.relay_model = config.relay_model
  return out
}

export const honeypotAPI = {
  /** 创建蜜罐 Key；返回的 key 为明文，仅此一次 */
  async createKey(payload: CreateHoneypotKeyPayload): Promise<{ api_key: HoneypotKeyItem; key: string }> {
    const { data } = await apiClient.post('/admin/honeypot/keys', {
      name: payload.name,
      config: normalizeConfig(payload.config)
    })
    return data
  },

  async listKeys(): Promise<{ items: HoneypotKeyItem[]; total: number }> {
    const { data } = await apiClient.get('/admin/honeypot/keys')
    return data
  },

  async updateKey(
    id: number,
    payload: { status?: string; config?: HoneypotConfig }
  ): Promise<{ api_key: HoneypotKeyItem }> {
    const body: Record<string, unknown> = {}
    if (payload.status) body.status = payload.status
    if (payload.config) body.config = normalizeConfig(payload.config)
    const { data } = await apiClient.put(`/admin/honeypot/keys/${id}`, body)
    return data
  },

  /** 将已泄露的真实 Key 原地转为蜜罐；replacement_key 明文仅此一次 */
  async convertKey(
    payload: ConvertHoneypotKeyPayload
  ): Promise<{ api_key: HoneypotKeyItem; replacement_api_key?: unknown; replacement_key?: string }> {
    const { data } = await apiClient.post('/admin/honeypot/convert', {
      key_id: payload.key_id,
      config: normalizeConfig(payload.config),
      issue_replacement: payload.issue_replacement
    })
    return data
  },

  async listEvents(params: {
    api_key_id?: number
    page?: number
    page_size?: number
  }): Promise<HoneypotEventListResult> {
    const { data } = await apiClient.get('/admin/honeypot/events', { params })
    return data
  }
}

export default honeypotAPI
