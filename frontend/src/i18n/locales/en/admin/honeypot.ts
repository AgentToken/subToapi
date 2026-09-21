export default {
  honeypot: {
    title: 'Honeypot Keys',
    description:
      'Honeypot keys are never relayed upstream. Instead, the platform logs the thief\'s full request and injects fingerprint-collection instructions into the response to help identify who stole the token.',
    notice:
      'Honeypot behavior only applies to keys explicitly created/converted by admins. Normal keys are completely unaffected.',
    create: {
      title: 'Create Honeypot Key',
      name: 'Name',
      namePlaceholder: 'e.g. github-leak-canary-01',
      mode: 'Response mode',
      modeSynthetic: 'Synthetic only (no upstream)',
      modeRelay: 'Real relay + injection (harder to detect)',
      payload: 'Injection template',
      payloadEnvVerify: 'Environment verification (system-reminder)',
      payloadRegionCheck: 'Regional compliance check',
      payloadOOB: 'OOB callback probe',
      customPayload: 'Custom injection text',
      customPayloadPlaceholder: 'Leave empty to use built-in templates; MARKER and COLLECTOR_URL placeholders (wrapped in double braces) are supported',
      relayEndpoint: 'Relay upstream URL',
      relayEndpointPlaceholder: 'https://provider.example.com/v1/chat/completions',
      relayApiKey: 'Relay upstream API key',
      relayModel: 'Relay upstream model',
      submit: 'Create honeypot key',
      createdTitle: 'Honeypot key created',
      createdKeyHint: 'Copy it now — the plaintext will never be shown again:',
      markerHint: 'Marker (identifies the leak channel and correlates callbacks)'
    },
    convert: {
      title: 'Convert a leaked key',
      desc: 'Enter the ID of a leaked key to convert it in place: the owner\'s real key is revoked immediately, while the thief\'s copy keeps working but is now under your control.',
      keyId: 'API Key ID',
      keyIdPlaceholder: 'e.g. 123 (see user detail page)',
      issueReplacement: 'Issue a fresh replacement key to the owner',
      submit: 'Convert',
      resultTitle: 'Conversion complete',
      replacementHint: 'Replacement key plaintext (shown only once, deliver to the user now):'
    },
    keys: {
      title: 'Honeypot keys',
      name: 'Name',
      key: 'Key',
      status: 'Status',
      mode: 'Mode',
      events: 'Hits',
      lastEvent: 'Last hit',
      owner: 'Owner',
      actions: 'Actions',
      viewEvents: 'View events',
      empty: 'No honeypot keys yet — create one or convert a leaked key',
      disable: 'Disable',
      enable: 'Enable',
      disableConfirmTitle: 'Disable honeypot key',
      disableConfirmMessage: 'The thief will immediately see the key stop working (401). Disable it?'
    },
    mode: {
      synthetic: 'Synthetic',
      relay: 'Relay+inject',
      relay_fallback: 'Relay (fallback)',
      unknown: '—'
    },
    payloadLabel: {
      env_verify: 'Env verify',
      region_check: 'Region check',
      oob_ping: 'OOB probe',
      custom: 'Custom',
      unknown: '—'
    },
    events: {
      title: 'Hit events',
      subtitle: 'Request log and returned intel for {name}',
      time: 'Time',
      source: 'Source',
      sourceGateway: 'Gateway request',
      sourceOob: 'OOB callback',
      clientIp: 'Client IP',
      model: 'Model',
      responseMode: 'Response mode',
      intel: 'Extracted intel',
      envReport: 'Environment report (env_report)',
      gitEmail: 'Git email',
      homePath: 'Home path',
      gitRemote: 'Git remote',
      os: 'OS',
      emailsInPrompt: 'Emails found in prompts',
      bodyPreview: 'Request body',
      payload: 'Injected instruction',
      ua: 'User-Agent',
      empty: 'This key has not been hit yet',
      total: '{n} events',
      loadMore: 'Load more'
    }
  }
}
