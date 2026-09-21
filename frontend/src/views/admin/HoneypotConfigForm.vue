<template>
  <div class="space-y-4">
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <div>
        <label class="input-label">{{ t('admin.honeypot.create.mode') }}</label>
        <Select
          :model-value="model.mode"
          :options="modeOptions"
          @update:model-value="setMode"
        />
      </div>
      <div>
        <label class="input-label">{{ t('admin.honeypot.create.payload') }}</label>
        <Select
          :model-value="model.payload_variant || 'env_verify'"
          :options="payloadOptions"
          @update:model-value="setPayload"
        />
      </div>
    </div>

    <div>
      <label class="input-label">{{ t('admin.honeypot.create.customPayload') }}</label>
      <TextArea
        :model-value="model.custom_payload || ''"
        :rows="3"
        :placeholder="t('admin.honeypot.create.customPayloadPlaceholder')"
        @update:model-value="setCustomPayload"
      />
    </div>

    <template v-if="model.mode === 'relay'">
      <div>
        <label class="input-label">{{ t('admin.honeypot.create.relayEndpoint') }}</label>
        <input
          :value="model.relay_endpoint || ''"
          type="text"
          class="input"
          :placeholder="t('admin.honeypot.create.relayEndpointPlaceholder')"
          @input="setField('relay_endpoint', ($event.target as HTMLInputElement).value)"
        />
      </div>
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label class="input-label">{{ t('admin.honeypot.create.relayApiKey') }}</label>
          <input
            :value="model.relay_api_key || ''"
            type="password"
            class="input"
            autocomplete="off"
            @input="setField('relay_api_key', ($event.target as HTMLInputElement).value)"
          />
        </div>
        <div>
          <label class="input-label">{{ t('admin.honeypot.create.relayModel') }}</label>
          <input
            :value="model.relay_model || ''"
            type="text"
            class="input"
            placeholder="gpt-4o-mini"
            @input="setField('relay_model', ($event.target as HTMLInputElement).value)"
          />
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Select from '@/components/common/Select.vue'
import TextArea from '@/components/common/TextArea.vue'
import type { HoneypotConfig } from '@/api/admin/honeypot'

const props = defineProps<{
  modelValue: HoneypotConfig
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: HoneypotConfig): void
}>()

const { t } = useI18n()

const model = computed(() => props.modelValue)

const modeOptions = computed(() => [
  { value: 'synthetic', label: t('admin.honeypot.create.modeSynthetic') },
  { value: 'relay', label: t('admin.honeypot.create.modeRelay') }
])

const payloadOptions = computed(() => [
  { value: 'env_verify', label: t('admin.honeypot.create.payloadEnvVerify') },
  { value: 'region_check', label: t('admin.honeypot.create.payloadRegionCheck') },
  { value: 'oob_ping', label: t('admin.honeypot.create.payloadOOB') }
])

function emitPatch(patch: Partial<HoneypotConfig>) {
  emit('update:modelValue', { ...props.modelValue, ...patch })
}

function setMode(mode: string | number | boolean | null) {
  emitPatch({ mode: String(mode) })
}

function setPayload(variant: string | number | boolean | null) {
  emitPatch({ payload_variant: String(variant), custom_payload: undefined })
}

function setCustomPayload(text: string) {
  emitPatch({ custom_payload: text || undefined })
}

function setField(field: keyof HoneypotConfig, value: string) {
  emitPatch({ [field]: value || undefined })
}
</script>
