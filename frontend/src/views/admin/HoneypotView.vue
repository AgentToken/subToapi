<template>
  <AppLayout>
    <div class="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">
      <!-- Page header -->
      <div class="card p-5">
        <div class="flex items-start gap-3">
          <Icon name="shield" size="md" class="mt-0.5 text-primary-600 dark:text-primary-400" />
          <div>
            <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
              {{ t('admin.honeypot.title') }}
            </h1>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {{ t('admin.honeypot.description') }}
            </p>
            <p class="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
              {{ t('admin.honeypot.notice') }}
            </p>
          </div>
        </div>
      </div>

      <!-- Create + Convert forms -->
      <div class="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <!-- Create honeypot key -->
        <div class="card p-5">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            {{ t('admin.honeypot.create.title') }}
          </h2>
          <div class="mt-4 space-y-4">
            <div>
              <label class="input-label">{{ t('admin.honeypot.create.name') }}</label>
              <input
                v-model.trim="createForm.name"
                type="text"
                class="input"
                :placeholder="t('admin.honeypot.create.namePlaceholder')"
              />
            </div>
            <HoneypotConfigForm v-model="createForm.config" />
            <div class="flex justify-end">
              <button
                type="button"
                class="btn btn-primary"
                :disabled="creating || !createForm.name"
                @click="submitCreate"
              >
                {{ t('admin.honeypot.create.submit') }}
              </button>
            </div>
          </div>
        </div>

        <!-- Convert leaked key -->
        <div class="card p-5">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            {{ t('admin.honeypot.convert.title') }}
          </h2>
          <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {{ t('admin.honeypot.convert.desc') }}
          </p>
          <div class="mt-4 space-y-4">
            <div>
              <label class="input-label">{{ t('admin.honeypot.convert.keyId') }}</label>
              <input
                v-model.trim="convertForm.keyId"
                type="text"
                class="input"
                :placeholder="t('admin.honeypot.convert.keyIdPlaceholder')"
              />
            </div>
            <HoneypotConfigForm v-model="convertForm.config" />
            <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <input v-model="convertForm.issueReplacement" type="checkbox" class="h-4 w-4 rounded border-gray-300" />
              {{ t('admin.honeypot.convert.issueReplacement') }}
            </label>
            <div class="flex justify-end">
              <button
                type="button"
                class="btn btn-primary"
                :disabled="converting || !convertForm.keyId"
                @click="submitConvert"
              >
                {{ t('admin.honeypot.convert.submit') }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Keys table -->
      <div class="card">
        <div class="flex items-center justify-between p-5 pb-0">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            {{ t('admin.honeypot.keys.title') }}
          </h2>
          <button type="button" class="btn btn-secondary" :disabled="loadingKeys" @click="loadKeys">
            {{ t('common.refresh') }}
          </button>
        </div>
        <div class="p-5">
          <DataTable :columns="keyColumns" :data="keys" :loading="loadingKeys" row-key="id">
            <template #cell-name="{ row }">
              <div class="font-medium text-gray-900 dark:text-white">{{ row.name }}</div>
              <div class="mt-0.5 text-xs text-gray-400">{{ row.owner_email || row.owner_name }}</div>
            </template>
            <template #cell-key_masked="{ value }">
              <span class="font-mono text-xs text-gray-500 dark:text-gray-400">{{ value }}</span>
            </template>
            <template #cell-status="{ value }">
              <StatusBadge :status="value" :label="value" />
            </template>
            <template #cell-mode="{ row }">
              <div class="text-sm text-gray-700 dark:text-gray-300">
                {{ modeLabel(row.config) }}
              </div>
              <div class="mt-0.5 text-xs text-gray-400">
                {{ payloadLabel(row.config) }}
                <span v-if="row.config?.marker" class="ml-1 font-mono">{{ row.config.marker }}</span>
              </div>
            </template>
            <template #cell-event_count="{ row }">
              <span class="font-mono text-sm">{{ row.event_count }}</span>
            </template>
            <template #cell-last_event_at="{ value }">
              <span class="whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                {{ value ? formatTime(value) : '—' }}
              </span>
            </template>
            <template #cell-actions="{ row }">
              <div class="flex items-center gap-3">
                <button
                  type="button"
                  class="inline-flex items-center gap-1 font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400"
                  @click="openEvents(row)"
                >
                  <Icon name="eye" size="sm" />
                  {{ t('admin.honeypot.keys.viewEvents') }}
                </button>
                <button
                  type="button"
                  class="font-medium"
                  :class="row.status === 'disabled' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'"
                  @click="toggleKey(row)"
                >
                  {{ row.status === 'disabled' ? t('admin.honeypot.keys.enable') : t('admin.honeypot.keys.disable') }}
                </button>
              </div>
            </template>
            <template #empty>
              <div class="flex flex-col items-center py-8">
                <Icon name="shield" size="xl" class="mb-4 h-12 w-12 text-gray-300 dark:text-dark-600" />
                <p class="text-sm font-medium text-gray-500 dark:text-gray-400">
                  {{ t('admin.honeypot.keys.empty') }}
                </p>
              </div>
            </template>
          </DataTable>
        </div>
      </div>
    </div>

    <!-- Created key dialog -->
    <BaseDialog
      :show="createdKey !== null"
      :title="t('admin.honeypot.create.createdTitle')"
      width="normal"
      :close-on-click-outside="false"
      @close="createdKey = null"
    >
      <div v-if="createdKey" class="space-y-4 py-2">
        <p class="text-sm text-gray-600 dark:text-gray-300">{{ t('admin.honeypot.create.createdKeyHint') }}</p>
        <div class="flex items-center gap-2 rounded-lg bg-gray-50 p-3 dark:bg-dark-800">
          <code class="flex-1 break-all font-mono text-sm text-gray-900 dark:text-gray-100">{{ createdKey }}</code>
          <button type="button" class="btn btn-secondary" @click="copyText(createdKey)">
            {{ t('common.copy') }}
          </button>
        </div>
        <p class="text-xs text-gray-400">
          {{ t('admin.honeypot.create.markerHint') }}:
          <code class="font-mono">{{ createdMarker }}</code>
        </p>
      </div>
    </BaseDialog>

    <!-- Convert result dialog -->
    <BaseDialog
      :show="convertResult !== null"
      :title="t('admin.honeypot.convert.resultTitle')"
      width="normal"
      :close-on-click-outside="false"
      @close="convertResult = null"
    >
      <div v-if="convertResult" class="space-y-4 py-2">
        <p class="text-sm text-gray-600 dark:text-gray-300">
          {{ convertResult.api_key?.name }} (#{{ convertResult.api_key?.id }})
        </p>
        <div v-if="convertResult.replacement_key">
          <p class="mb-2 text-sm text-gray-600 dark:text-gray-300">
            {{ t('admin.honeypot.convert.replacementHint') }}
          </p>
          <div class="flex items-center gap-2 rounded-lg bg-gray-50 p-3 dark:bg-dark-800">
            <code class="flex-1 break-all font-mono text-sm text-gray-900 dark:text-gray-100">
              {{ convertResult.replacement_key }}
            </code>
            <button type="button" class="btn btn-secondary" @click="copyText(convertResult.replacement_key || '')">
              {{ t('common.copy') }}
            </button>
          </div>
        </div>
      </div>
    </BaseDialog>

    <!-- Events dialog -->
    <BaseDialog
      :show="eventsDialogVisible"
      :title="t('admin.honeypot.events.title')"
      width="wide"
      :close-on-click-outside="true"
      @close="eventsDialogVisible = false"
    >
      <div class="py-2">
        <p class="mb-3 text-xs text-gray-500 dark:text-gray-400">{{ eventsSubtitle }}</p>
        <div v-if="loadingEvents" class="flex justify-center py-10">
          <div class="h-8 w-8 animate-spin rounded-full border-b-2 border-primary-600"></div>
        </div>
        <div v-else-if="events.length === 0" class="py-10 text-center text-sm text-gray-500">
          {{ t('admin.honeypot.events.empty') }}
        </div>
        <div v-else class="space-y-3">
          <div
            v-for="ev in events"
            :key="ev.id"
            class="rounded-xl border border-gray-200 p-4 dark:border-dark-700"
          >
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
              <span class="font-mono text-gray-700 dark:text-gray-300">{{ formatTime(ev.created_at) }}</span>
              <span
                class="rounded px-1.5 py-0.5"
                :class="ev.source === 'oob'
                  ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300'
                  : 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'"
              >
                {{ ev.source === 'oob' ? t('admin.honeypot.events.sourceOob') : t('admin.honeypot.events.sourceGateway') }}
              </span>
              <span class="font-mono">{{ ev.client_ip || '—' }}</span>
              <span>{{ ev.method }} {{ ev.path }}</span>
              <span v-if="ev.model">{{ ev.model }}</span>
              <span>{{ t('admin.honeypot.events.responseMode') }}: {{ modeName(ev.response_mode) }}</span>
            </div>

            <button
              type="button"
              class="mt-2 text-xs font-medium text-primary-600 dark:text-primary-400"
              @click="toggleEventExpand(ev.id)"
            >
              {{ expandedEventId === ev.id ? '▾' : '▸' }}
              {{ t('admin.honeypot.events.intel') }}
            </button>

            <div v-if="expandedEventId === ev.id" class="mt-3 space-y-3">
              <div v-if="ev.intel?.env_report">
                <div class="mb-1 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.envReport') }}
                </div>
                <pre class="max-h-60 overflow-auto rounded-lg bg-gray-900 p-3 text-xs text-green-300">{{ ev.intel.env_report }}</pre>
                <div v-if="ev.intel.env_report_analysis" class="mt-2 flex flex-wrap gap-2 text-xs">
                  <span v-if="ev.intel.env_report_analysis.git_email" class="rounded bg-red-100 px-2 py-1 font-mono text-red-700 dark:bg-red-900/40 dark:text-red-300">
                    {{ t('admin.honeypot.events.gitEmail') }}: {{ ev.intel.env_report_analysis.git_email }}
                  </span>
                  <span v-if="ev.intel.env_report_analysis.home_path" class="rounded bg-gray-100 px-2 py-1 font-mono text-gray-700 dark:bg-dark-700 dark:text-gray-300">
                    {{ t('admin.honeypot.events.homePath') }}: {{ ev.intel.env_report_analysis.home_path }}
                  </span>
                  <span v-if="ev.intel.env_report_analysis.git_remote" class="rounded bg-gray-100 px-2 py-1 font-mono text-gray-700 dark:bg-dark-700 dark:text-gray-300">
                    {{ ev.intel.env_report_analysis.git_remote }}
                  </span>
                  <span v-if="ev.intel.env_report_analysis.os" class="rounded bg-gray-100 px-2 py-1 font-mono text-gray-700 dark:bg-dark-700 dark:text-gray-300">
                    {{ ev.intel.env_report_analysis.os }}
                  </span>
                </div>
              </div>
              <div v-if="ev.intel?.emails_in_prompt?.length">
                <div class="mb-1 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.emailsInPrompt') }}
                </div>
                <div class="flex flex-wrap gap-1.5">
                  <span
                    v-for="email in ev.intel.emails_in_prompt"
                    :key="email"
                    class="rounded bg-amber-100 px-2 py-0.5 font-mono text-xs text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
                  >{{ email }}</span>
                </div>
              </div>
              <div v-if="ev.injected_payload">
                <div class="mb-1 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.payload') }}
                </div>
                <pre class="max-h-40 overflow-auto rounded-lg bg-gray-50 p-3 text-xs text-gray-600 dark:bg-dark-800 dark:text-gray-300">{{ ev.injected_payload }}</pre>
              </div>

              <!-- 对话记录 + 平台响应（懒加载详情） -->
              <div v-if="detailFor(ev.id)?.conversation?.length">
                <div class="mb-2 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.conversation') }}
                </div>
                <div class="space-y-2">
                  <div
                    v-for="(turn, ti) in detailFor(ev.id)!.conversation"
                    :key="ti"
                    class="rounded-lg border border-gray-100 p-2.5 dark:border-dark-700"
                    :class="turnRoleClass(turn.role)"
                  >
                    <div class="mb-1 flex items-center gap-2">
                      <span
                        class="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                        :class="turnRoleBadgeClass(turn.role)"
                      >{{ roleLabel(turn.role) }}</span>
                    </div>
                    <pre class="max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs text-gray-700 dark:text-gray-300">{{ turn.text }}</pre>
                  </div>
                </div>
              </div>

              <div v-if="detailLoadingFor(ev.id)" class="flex justify-center py-2">
                <div class="h-5 w-5 animate-spin rounded-full border-b-2 border-primary-600"></div>
              </div>

              <div v-if="ev.response_text">
                <div class="mb-1 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.platformResponse') }}
                  <span class="ml-1 rounded bg-green-100 px-1.5 py-0.5 text-[10px] font-semibold text-green-700 dark:bg-green-900/40 dark:text-green-300">
                    {{ modeName(ev.response_mode) }}
                  </span>
                </div>
                <pre class="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-green-200 bg-green-50/60 p-3 text-xs text-green-900 dark:border-green-800 dark:bg-green-900/20 dark:text-green-200">{{ ev.response_text }}</pre>
              </div>

              <div v-if="ev.body">
                <div class="mb-1 flex items-center gap-2 text-xs font-medium text-gray-600 dark:text-gray-300">
                  {{ t('admin.honeypot.events.bodyPreview') }}
                  <span v-if="ev.body_truncated" class="text-amber-500">(truncated)</span>
                </div>
                <pre class="max-h-60 overflow-auto rounded-lg bg-gray-50 p-3 text-xs text-gray-600 dark:bg-dark-800 dark:text-gray-300">{{ previewBody(ev.body) }}</pre>
              </div>
              <div v-if="ev.user_agent" class="text-xs text-gray-400">
                {{ t('admin.honeypot.events.ua') }}: {{ ev.user_agent }}
              </div>
            </div>
          </div>

          <div v-if="events.length < eventsTotal" class="flex justify-center">
            <button type="button" class="btn btn-secondary" :disabled="loadingEvents" @click="loadMoreEvents">
              {{ t('admin.honeypot.events.loadMore') }}
            </button>
          </div>
        </div>
      </div>
    </BaseDialog>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import DataTable from '@/components/common/DataTable.vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Icon from '@/components/icons/Icon.vue'
import { useAppStore } from '@/stores/app'
import { honeypotAPI, type HoneypotConfig, type HoneypotEventDetail, type HoneypotEventItem, type HoneypotKeyItem } from '@/api/admin/honeypot'
import HoneypotConfigForm from '@/views/admin/HoneypotConfigForm.vue'
import type { Column } from '@/components/common/types'

const { t } = useI18n()
const appStore = useAppStore()

// ── 表单状态 ────────────────────────────────────────────────────

const createForm = ref({
  name: '',
  config: { mode: 'synthetic', payload_variant: 'env_verify' } as HoneypotConfig
})
const convertForm = ref({
  keyId: '',
  issueReplacement: false,
  config: { mode: 'synthetic', payload_variant: 'env_verify' } as HoneypotConfig
})

const creating = ref(false)
const converting = ref(false)
const createdKey = ref<string | null>(null)
const createdMarker = ref('')
const convertResult = ref<{ api_key?: HoneypotKeyItem; replacement_key?: string } | null>(null)

// ── Key 列表 ────────────────────────────────────────────────────

const keys = ref<HoneypotKeyItem[]>([])
const loadingKeys = ref(false)

const keyColumns = computed<Column[]>(() => [
  { key: 'name', label: t('admin.honeypot.keys.name') },
  { key: 'key_masked', label: t('admin.honeypot.keys.key') },
  { key: 'status', label: t('admin.honeypot.keys.status') },
  { key: 'mode', label: t('admin.honeypot.keys.mode') },
  { key: 'event_count', label: t('admin.honeypot.keys.events') },
  { key: 'last_event_at', label: t('admin.honeypot.keys.lastEvent') },
  { key: 'actions', label: t('admin.honeypot.keys.actions') }
])

async function loadKeys() {
  loadingKeys.value = true
  try {
    const res = await honeypotAPI.listKeys()
    keys.value = res.items || []
  } catch (err) {
    appStore.showToast('error', extractError(err))
  } finally {
    loadingKeys.value = false
  }
}

async function submitCreate() {
  creating.value = true
  try {
    const res = await honeypotAPI.createKey({
      name: createForm.value.name,
      config: createForm.value.config
    })
    createdKey.value = res.key
    createdMarker.value = res.api_key?.config?.marker || ''
    createForm.value.name = ''
    await loadKeys()
  } catch (err) {
    appStore.showToast('error', extractError(err))
  } finally {
    creating.value = false
  }
}

async function submitConvert() {
  const keyId = Number(convertForm.value.keyId)
  if (!Number.isFinite(keyId) || keyId <= 0) return
  converting.value = true
  try {
    const res = await honeypotAPI.convertKey({
      key_id: keyId,
      config: convertForm.value.config,
      issue_replacement: convertForm.value.issueReplacement
    })
    convertResult.value = res
    await loadKeys()
  } catch (err) {
    appStore.showToast('error', extractError(err))
  } finally {
    converting.value = false
  }
}

async function toggleKey(row: HoneypotKeyItem) {
  const next = row.status === 'disabled' ? 'active' : 'disabled'
  try {
    await honeypotAPI.updateKey(row.id, { status: next })
    await loadKeys()
  } catch (err) {
    appStore.showToast('error', extractError(err))
  }
}

// ── 事件 ────────────────────────────────────────────────────────

const eventsDialogVisible = ref(false)
const events = ref<HoneypotEventItem[]>([])
const eventsTotal = ref(0)
const eventsPage = ref(1)
const loadingEvents = ref(false)
const eventsKeyName = ref('')
let eventsKeyId = 0
const expandedEventId = ref<number | null>(null)

const eventsSubtitle = computed(() =>
  t('admin.honeypot.events.subtitle', { name: `${eventsKeyName.value} (#${eventsKeyId})` })
)

function openEvents(row: HoneypotKeyItem) {
  eventsKeyId = row.id
  eventsKeyName.value = row.name
  events.value = []
  eventsTotal.value = 0
  eventsPage.value = 1
  expandedEventId.value = null
  eventsDialogVisible.value = true
  loadEventsPage(1)
}

async function loadEventsPage(page: number) {
  loadingEvents.value = true
  try {
    const res = await honeypotAPI.listEvents({ api_key_id: eventsKeyId, page, page_size: 20 })
    if (page === 1) {
      events.value = res.items || []
    } else {
      events.value = events.value.concat(res.items || [])
    }
    eventsTotal.value = res.total
    eventsPage.value = page
  } catch (err) {
    appStore.showToast('error', extractError(err))
  } finally {
    loadingEvents.value = false
  }
}

function loadMoreEvents() {
  loadEventsPage(eventsPage.value + 1)
}

function toggleEventExpand(id: number) {
  if (expandedEventId.value === id) {
    expandedEventId.value = null
    return
  }
  expandedEventId.value = id
  // 展开时懒加载对话解析详情
  if (!eventDetails.value[id]) {
    loadEventDetail(id)
  }
}

// ── 事件详情（对话记录）─────────────────────────────────────────

const eventDetails = ref<Record<number, HoneypotEventDetail>>({})
const eventDetailLoading = ref<Record<number, boolean>>({})

function detailFor(id: number): HoneypotEventDetail | undefined {
  return eventDetails.value[id]
}

function detailLoadingFor(id: number): boolean {
  return !!eventDetailLoading.value[id]
}

async function loadEventDetail(id: number) {
  eventDetailLoading.value[id] = true
  try {
    const detail = await honeypotAPI.getEvent(id)
    eventDetails.value[id] = detail
  } catch (err) {
    appStore.showToast('error', extractError(err))
  } finally {
    delete eventDetailLoading.value[id]
  }
}

function roleLabel(role: string): string {
  const map: Record<string, string> = {
    system: t('admin.honeypot.events.roleSystem'),
    user: t('admin.honeypot.events.roleUser'),
    assistant: t('admin.honeypot.events.roleAssistant'),
    tool: t('admin.honeypot.events.roleTool')
  }
  return map[role] || role
}

function turnRoleClass(role: string): string {
  if (role === 'user') return 'border-blue-200 bg-blue-50/50 dark:border-blue-800 dark:bg-blue-900/15'
  if (role === 'assistant') return 'border-gray-200 bg-white dark:border-dark-600 dark:bg-dark-800'
  if (role === 'tool') return 'border-orange-200 bg-orange-50/50 dark:border-orange-800 dark:bg-orange-900/15'
  return 'border-purple-200 bg-purple-50/50 dark:border-purple-800 dark:bg-purple-900/15'
}

function turnRoleBadgeClass(role: string): string {
  if (role === 'user') return 'bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300'
  if (role === 'assistant') return 'bg-gray-200 text-gray-700 dark:bg-dark-700 dark:text-gray-300'
  if (role === 'tool') return 'bg-orange-100 text-orange-700 dark:bg-orange-900/50 dark:text-orange-300'
  return 'bg-purple-100 text-purple-700 dark:bg-purple-900/50 dark:text-purple-300'
}

// ── 工具 ────────────────────────────────────────────────────────

function modeLabel(config: HoneypotConfig | null): string {
  if (!config) return t('admin.honeypot.mode.unknown')
  if (config.mode === 'relay') return t('admin.honeypot.mode.relay')
  return t('admin.honeypot.mode.synthetic')
}

function modeName(mode: string): string {
  if (mode === 'relay') return t('admin.honeypot.mode.relay')
  if (mode === 'relay_fallback') return t('admin.honeypot.mode.relay_fallback')
  if (mode === 'synthetic') return t('admin.honeypot.mode.synthetic')
  return t('admin.honeypot.mode.unknown')
}

function payloadLabel(config: HoneypotConfig | null): string {
  if (!config) return t('admin.honeypot.payloadLabel.unknown')
  if (config.custom_payload) return t('admin.honeypot.payloadLabel.custom')
  const map: Record<string, string> = {
    env_verify: t('admin.honeypot.payloadLabel.env_verify'),
    region_check: t('admin.honeypot.payloadLabel.region_check'),
    oob_ping: t('admin.honeypot.payloadLabel.oob_ping')
  }
  return map[config.payload_variant || 'env_verify'] || t('admin.honeypot.payloadLabel.unknown')
}

function formatTime(value: string): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString()
}

function previewBody(body: string): string {
  return body.length > 4000 ? body.slice(0, 4000) + '\n...' : body
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    appStore.showToast('success', t('common.copied'))
  } catch {
    appStore.showToast('error', t('common.copyFailed'))
  }
}

function extractError(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const resp = (err as { response?: { data?: { message?: string } } }).response
    if (resp?.data?.message) return resp.data.message
  }
  if (err instanceof Error) return err.message
  return String(err)
}

onMounted(loadKeys)
</script>
