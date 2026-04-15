import { useEffect, useState } from 'react'
import RiskBadge from './RiskBadge'

function formatList(values, fallback = 'None detected') {
  if (!Array.isArray(values) || values.length === 0) {
    return fallback
  }
  return values.join(', ')
}

function flattenAssets(assets) {
  if (Array.isArray(assets)) {
    return assets
  }

  if (!assets || typeof assets !== 'object') {
    return []
  }

  return Object.values(assets).flat().filter(Boolean)
}

function toPercent(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0
  }
  return value <= 1 ? Math.round(value * 100) : Math.round(value)
}

function CaseDetailPanel({ selectedCase, onSave, onReportToCyberCell }) {
  const [caseStatus, setCaseStatus] = useState('new')
  const [owner, setOwner] = useState('Unassigned')
  const [businessUnit, setBusinessUnit] = useState('Security Operations')
  const [comment, setComment] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!selectedCase) {
      return
    }
    setCaseStatus(selectedCase.case_status || 'new')
    setOwner(selectedCase.owner || 'Unassigned')
    setBusinessUnit(selectedCase.business_unit || 'Security Operations')
    setComment('')
  }, [selectedCase])

  if (!selectedCase) {
    return (
      <div className="glass-card neon-panel rounded-[32px] p-6 text-slate-400">
        Select a case from the inbox to review evidence, ownership, and recommended actions.
      </div>
    )
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave(selectedCase.id, {
        case_status: caseStatus,
        owner,
        business_unit: businessUnit,
        comment: comment.trim() || undefined,
      })
      setComment('')
    } finally {
      setSaving(false)
    }
  }

  const assetSections = [
    ['Domains', selectedCase.affected_assets?.domains],
    ['Emails', selectedCase.affected_assets?.emails],
    ['IPs', selectedCase.affected_assets?.ips],
    ['Usernames', selectedCase.affected_assets?.usernames],
    ['Tokens', selectedCase.affected_assets?.tokens],
    ['Wallets', selectedCase.affected_assets?.wallets],
  ]
  const evidenceItems = selectedCase.evidence || []
  const executiveSummary = selectedCase.exposure_summary || selectedCase.executive_summary || selectedCase.summary
  const technicalSummary =
    selectedCase.technical_summary && selectedCase.technical_summary !== executiveSummary
      ? selectedCase.technical_summary
      : ''
  const corroborationText =
    (selectedCase.source_count || 0) <= 1
      ? 'This case currently relies on one monitored source.'
      : `${selectedCase.corroborating_source_count || 0} additional corroborating source(s) support this case.`
  const confidencePercent = toPercent(selectedCase.confidence_score || 0)
  const attentionReasons = selectedCase.why_flagged || selectedCase.why_this_was_flagged || selectedCase.confidence_assessment?.reasons || []

  return (
    <div className="glass-card neon-panel rounded-[32px] p-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Case Detail</p>
          <h3 className="mt-2 text-2xl font-semibold text-white">{selectedCase.title}</h3>
          <p className="mt-3 text-sm text-slate-300">{executiveSummary}</p>
          {technicalSummary ? <p className="mt-3 text-sm text-slate-400">{technicalSummary}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <RiskBadge level={selectedCase.risk_level || 'LOW'} />
          <div className="terminal-text rounded-full border border-[#FF3B3B]/20 bg-[#FF3B3B]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#FFB4B4]">
            Severity {selectedCase.severity || 'Low'}
          </div>
          <div className="terminal-text rounded-full border border-[#00E5FF]/20 bg-[#00E5FF]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]">
            Priority {selectedCase.priority}
          </div>
          <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
            Confidence {confidencePercent}%
          </div>
          <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
            {selectedCase.triage_status || selectedCase.case_status}
          </div>
          {onReportToCyberCell ? (
            <button
              type="button"
              onClick={() => onReportToCyberCell(selectedCase)}
              className="terminal-text rounded-full border border-[#FF3B3B]/30 bg-[#FF3B3B]/10 px-4 py-1 text-[11px] uppercase tracking-[0.24em] text-[#FFD0D0]"
            >
              Report To Cyber Cell
            </button>
          ) : null}
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Confirmed organization assets</p>
          <p className="mt-2 text-sm text-slate-200">{formatList(flattenAssets(selectedCase.affected_assets), 'Unknown assets')}</p>
        </div>
        <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Confirmed exposed data</p>
          <p className="mt-2 text-sm text-slate-200">{formatList(selectedCase.exposed_data_types, 'Undetermined')}</p>
        </div>
        <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Estimated exposure size</p>
          <p className="mt-2 text-sm text-slate-200">{selectedCase.estimated_total_records_label || 'Unknown exposure'}</p>
        </div>
        <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Source support</p>
          <p className="mt-2 text-sm text-slate-200">{corroborationText}</p>
        </div>
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-[1fr_0.9fr]">
        <div className="space-y-4">
          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Why this case needs attention</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-200">
              {attentionReasons.map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>
          {selectedCase.severity_reason ? (
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Why the severity was assigned</p>
              <p className="mt-3 text-sm text-slate-200">{selectedCase.severity_reason}</p>
            </div>
          ) : null}
          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Confirmed organization assets</p>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              {assetSections.map(([label, values]) => (
                <div key={label} className="rounded-[18px] border border-white/8 bg-white/5 p-3">
                  <p className="text-xs uppercase tracking-[0.22em] text-slate-500">{label}</p>
                  <p className="mt-2 text-sm text-slate-200">{formatList(values, 'None')}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Recommended Actions</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-200">
              {(selectedCase.recommended_actions || []).map((action) => (
                <li key={action}>• {action}</li>
              ))}
            </ul>
          </div>
          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Evidence and reasoning</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-200">
              {(selectedCase.confidence_basis || []).map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Investigation workflow</p>
            <div className="mt-4 space-y-3">
              <label className="block">
                <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Status</span>
                <select
                  value={caseStatus}
                  onChange={(event) => setCaseStatus(event.target.value)}
                  className="mt-2 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                >
                  <option value="new">New</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </label>
              <label className="block">
                <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Owner</span>
                <input
                  value={owner}
                  onChange={(event) => setOwner(event.target.value)}
                  className="mt-2 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Business Unit</span>
                <input
                  value={businessUnit}
                  onChange={(event) => setBusinessUnit(event.target.value)}
                  className="mt-2 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Analyst Note</span>
                <textarea
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  className="mt-2 min-h-28 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                  placeholder="Add remediation notes or investigation context..."
                />
              </label>
              <button
                type="button"
                onClick={handleSave}
                disabled={saving}
                className="terminal-text rounded-[20px] bg-[linear-gradient(135deg,#00E5FF,#00FF9F)] px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-slate-950"
              >
                {saving ? 'Saving...' : 'Update Case'}
              </button>
            </div>
          </div>

          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Supporting evidence</p>
            <div className="mt-3 space-y-3">
              {evidenceItems.length ? (
                evidenceItems.slice(0, 4).map((item) => (
                  <div key={item.evidence_id} className="rounded-[18px] border border-white/8 bg-white/5 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-white">{item.source_platform || item.source || 'Unknown source'}</p>
                      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
                        {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown time'}
                      </p>
                    </div>
                    <p className="mt-2 text-sm text-slate-200">{item.cleaned_snippet || item.legacy_summary || item.raw_snippet}</p>
                    <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                      Related assets: {formatList(item.matched_entities, 'None')}
                    </p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-slate-400">No evidence preview available.</p>
              )}
            </div>
          </div>

          <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Where this was observed</p>
            <div className="mt-3 space-y-3">
              {(selectedCase.sources || []).map((source) => (
                <div key={`${source.source}-${source.first_seen}`} className="rounded-[18px] border border-white/8 bg-white/5 p-3">
                  <p className="text-sm font-semibold text-white">{source.source}</p>
                  <p className="mt-2 text-sm text-slate-300">
                    Locations: {formatList(source.source_locations, 'No source locations')}
                  </p>
                  <p className="mt-1 text-xs uppercase tracking-[0.22em] text-slate-500">
                    Evidence items {source.evidence_count || 0} | trust score {toPercent(source.trust_score || 0)} | last seen {source.last_seen ? new Date(source.last_seen).toLocaleString() : 'unknown'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CaseDetailPanel
