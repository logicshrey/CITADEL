import { useEffect, useMemo, useState } from 'react'
import { getCyberCellReportingStatus, previewCyberCellReport, sendCyberCellReport } from '../services/api'

function splitEmails(value) {
  return value
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function extractErrorMessage(apiError, fallback) {
  const detail = apiError?.response?.data?.detail
  if (typeof detail === 'string') {
    return detail
  }
  if (detail?.message && Array.isArray(detail?.reasons) && detail.reasons.length) {
    return `${detail.message} ${detail.reasons.join(' ')}`
  }
  if (detail?.message) {
    return detail.message
  }
  return fallback
}

function buildInitialState(defaultRequest) {
  return {
    recipientsText: (defaultRequest?.recipients || []).join(', '),
    ccText: (defaultRequest?.cc || []).join(', '),
    authorityLocation: defaultRequest?.authority_location || '',
    organizationName: defaultRequest?.organization_details?.organization_name || defaultRequest?.org_id || '',
    industry: defaultRequest?.organization_details?.industry || '',
    registeredAddress: defaultRequest?.organization_details?.registered_address || '',
    contactName: defaultRequest?.contact_person_details?.name || '',
    contactDesignation: defaultRequest?.contact_person_details?.designation || '',
    contactEmail: defaultRequest?.contact_person_details?.email || '',
    contactPhone: defaultRequest?.contact_person_details?.phone || '',
    includeJsonBundle: Boolean(defaultRequest?.include_json_bundle),
    confirmationFlag: false,
  }
}

function CyberCellReportModal({ isOpen, onClose, defaultRequest, onSuccess, onError }) {
  const [formState, setFormState] = useState(buildInitialState(defaultRequest))
  const [preview, setPreview] = useState(null)
  const [previewing, setPreviewing] = useState(false)
  const [sending, setSending] = useState(false)
  const [status, setStatus] = useState(null)
  const [statusLoading, setStatusLoading] = useState(false)

  useEffect(() => {
    if (!isOpen) {
      return
    }
    setFormState(buildInitialState(defaultRequest))
    setPreview(null)
    setPreviewing(false)
    setSending(false)
    setStatus(null)
  }, [isOpen, defaultRequest])

  useEffect(() => {
    if (!isOpen) {
      return
    }

    let active = true
    const loadStatus = async () => {
      setStatusLoading(true)
      try {
        const response = await getCyberCellReportingStatus()
        if (active) {
          setStatus(response)
        }
      } catch (apiError) {
        if (active) {
          onError(extractErrorMessage(apiError, 'Unable to verify cyber cell delivery status.'))
        }
      } finally {
        if (active) {
          setStatusLoading(false)
        }
      }
    }

    loadStatus()
    return () => {
      active = false
    }
  }, [isOpen, onError])

  const payload = useMemo(() => {
    return {
      case_ids: defaultRequest?.case_ids || [],
      org_id: defaultRequest?.org_id || undefined,
      date_range: defaultRequest?.date_range || undefined,
      severity: defaultRequest?.severity || [],
      recipients: splitEmails(formState.recipientsText),
      cc: splitEmails(formState.ccText),
      authority_location: formState.authorityLocation || undefined,
      contact_person_details: {
        name: formState.contactName,
        designation: formState.contactDesignation,
        email: formState.contactEmail,
        phone: formState.contactPhone,
      },
      organization_details: {
        organization_name: formState.organizationName || undefined,
        industry: formState.industry || undefined,
        registered_address: formState.registeredAddress || undefined,
      },
      include_json_bundle: formState.includeJsonBundle,
    }
  }, [defaultRequest, formState])

  if (!isOpen) {
    return null
  }

  const updateForm = (updates) => {
    setFormState((current) => ({ ...current, ...updates }))
    setPreview(null)
  }

  const handlePreview = async () => {
    setPreviewing(true)
    try {
      const response = await previewCyberCellReport(payload)
      setPreview(response)
    } catch (apiError) {
      onError(extractErrorMessage(apiError, 'Cyber cell report preview failed.'))
    } finally {
      setPreviewing(false)
    }
  }

  const handleSend = async () => {
    if (!preview?.preview_id) {
      onError('Generate a preview before sending the cyber cell report.')
      return
    }
    setSending(true)
    try {
      const response = await sendCyberCellReport({
        ...payload,
        preview_id: preview.preview_id,
        confirmation_flag: formState.confirmationFlag,
      })
      const deliveryLabel = response.delivery_mode === 'live' ? 'live email delivery confirmed' : 'mock delivery recorded'
      onSuccess(
        `Cyber cell report sent. ${deliveryLabel}. Audit ID ${response.audit_id}. Report ID ${response.report_id}. Timestamp ${response.timestamp}.`,
      )
      onClose()
    } catch (apiError) {
      onError(extractErrorMessage(apiError, 'Cyber cell report send failed.'))
    } finally {
      setSending(false)
    }
  }

  const sendDisabled =
    sending ||
    !formState.confirmationFlag ||
    !preview?.preview_id ||
    !preview?.eligible_cases_count ||
    Boolean(preview?.rejected_cases?.length) ||
    Boolean(status && !status.live_delivery_ready)

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 px-4 py-4 sm:py-6">
      <div className="flex min-h-full items-start justify-center">
        <div className="glass-card neon-panel flex max-h-[calc(100vh-2rem)] w-full max-w-6xl flex-col overflow-hidden rounded-[32px]">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/8 px-6 py-6">
            <div>
              <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Cyber Cell Reporting</p>
              <h3 className="mt-2 text-3xl font-semibold text-white">Preview and send an official complaint</h3>
              <p className="mt-3 max-w-3xl text-sm text-slate-300">
                This flow is limited to verified high-confidence cases and requires a preview before the report can be sent.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="rounded-[18px] border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200"
            >
              Close
            </button>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-6">
            <div className="mb-4 rounded-[22px] border border-white/8 bg-black/10 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Delivery status</p>
                  {statusLoading ? (
                    <p className="mt-2 text-sm text-slate-300">Checking reporting configuration...</p>
                  ) : status ? (
                    <>
                      <p className="mt-2 text-sm text-slate-200">
                        Mode: <span className="font-semibold text-white">{status.mode}</span> | Transport: {status.transport}
                      </p>
                      <p className="mt-1 text-sm text-slate-300">
                        {status.live_delivery_ready
                          ? 'Submitting this complaint will send it immediately through the configured SMTP provider.'
                          : 'Submitting will not reach real recipient inboxes until live reporting is configured.'}
                      </p>
                    </>
                  ) : (
                    <p className="mt-2 text-sm text-slate-300">Delivery configuration status is unavailable.</p>
                  )}
                </div>
                <div
                  className={`rounded-full border px-3 py-1 text-[11px] uppercase tracking-[0.24em] ${
                    status?.live_delivery_ready
                      ? 'border-[#00FF9F]/35 bg-[#00FF9F]/10 text-[#B8FFE0]'
                      : 'border-[#FFC857]/35 bg-[#FFC857]/10 text-[#FFE4A3]'
                  }`}
                >
                  {status?.live_delivery_ready ? 'Live Ready' : 'Configuration Required'}
                </div>
              </div>
              {status?.reasons?.length ? (
                <div className="mt-3 rounded-[18px] border border-[#FFC857]/25 bg-[#FFC857]/10 p-3 text-sm text-[#FFE4A3]">
                  {status.reasons.join(' ')}
                </div>
              ) : null}
            </div>

            <div className="grid gap-4 xl:grid-cols-[1fr_1.1fr]">
              <div className="space-y-4">
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Recipients</p>
                  <textarea
                    value={formState.recipientsText}
                    onChange={(event) => updateForm({ recipientsText: event.target.value })}
                    className="mt-2 min-h-24 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                    placeholder="cybercell@example.gov.in, noc@example.org"
                  />
                  <p className="mt-2 text-xs text-slate-500">Use commas, semicolons, or new lines to add multiple recipients.</p>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">CC and authority details</p>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <textarea
                      value={formState.ccText}
                      onChange={(event) => updateForm({ ccText: event.target.value })}
                      className="min-h-24 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="soc@example.org"
                    />
                    <input
                      value={formState.authorityLocation}
                      onChange={(event) => updateForm({ authorityLocation: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Authority location, for example Mumbai, India"
                    />
                  </div>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Organization details</p>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <input
                      value={formState.organizationName}
                      onChange={(event) => updateForm({ organizationName: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Organization name"
                    />
                    <input
                      value={formState.industry}
                      onChange={(event) => updateForm({ industry: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Industry"
                    />
                    <input
                      value={formState.registeredAddress}
                      onChange={(event) => updateForm({ registeredAddress: event.target.value })}
                      className="md:col-span-2 w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Registered address"
                    />
                  </div>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Contact person details</p>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <input
                      value={formState.contactName}
                      onChange={(event) => updateForm({ contactName: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Name"
                    />
                    <input
                      value={formState.contactDesignation}
                      onChange={(event) => updateForm({ contactDesignation: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Designation"
                    />
                    <input
                      value={formState.contactEmail}
                      onChange={(event) => updateForm({ contactEmail: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Email"
                    />
                    <input
                      value={formState.contactPhone}
                      onChange={(event) => updateForm({ contactPhone: event.target.value })}
                      className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                      placeholder="Phone number"
                    />
                  </div>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <label className="flex items-center gap-3 text-sm text-slate-200">
                    <input
                      type="checkbox"
                      checked={formState.includeJsonBundle}
                      onChange={(event) => updateForm({ includeJsonBundle: event.target.checked })}
                    />
                    Include JSON evidence bundle with the report
                  </label>
                  <label className="mt-3 flex items-start gap-3 text-sm text-slate-200">
                    <input
                      type="checkbox"
                      checked={formState.confirmationFlag}
                      onChange={(event) => setFormState((current) => ({ ...current, confirmationFlag: event.target.checked }))}
                    />
                    <span>I confirm this report is verified and accurate to the best of my knowledge.</span>
                  </label>
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Preview status</p>
                  {preview ? (
                    <div className="mt-3 space-y-3 text-sm text-slate-200">
                      <p>Eligible cases: {preview.eligible_cases_count || 0}</p>
                      <p>Preview token: {preview.preview_id || 'Not generated'}</p>
                      <p>Report ID: {preview.report_id || 'Pending'}</p>
                      <p>Signature status: {preview.signature_status || 'unsigned'}</p>
                      {preview.verification_url ? (
                        <p className="break-all text-[#CFFAFE]">
                          Verification URL:{' '}
                          <a href={preview.verification_url} target="_blank" rel="noreferrer" className="underline">
                            {preview.verification_url}
                          </a>
                        </p>
                      ) : null}
                      {preview.rejection_reasons?.length ? (
                        <div className="rounded-[18px] border border-[#FFC857]/25 bg-[#FFC857]/10 p-3 text-[#FFE4A3]">
                          {preview.rejection_reasons.join(' ')}
                        </div>
                      ) : null}
                    </div>
                  ) : (
                    <p className="mt-3 text-sm text-slate-400">Generate a preview to inspect the official complaint body and attachments.</p>
                  )}
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Selected cases</p>
                  <div className="mt-3 max-h-56 space-y-3 overflow-y-auto pr-1">
                    {(preview?.selected_cases || []).map((item) => (
                      <div key={item.case_id} className="rounded-[18px] border border-white/8 bg-white/5 p-3 text-sm text-slate-200">
                        <p className="font-semibold text-white">{item.title}</p>
                        <p className="mt-2">
                          Verification {item.verification_status} | Severity {item.severity} | Confidence {item.confidence_score}%
                        </p>
                        {item.rejection_reasons?.length ? (
                          <p className="mt-2 text-[#FFD0D0]">{item.rejection_reasons.join(' ')}</p>
                        ) : null}
                      </div>
                    ))}
                    {!preview?.selected_cases?.length ? <p className="text-sm text-slate-400">No preview generated yet.</p> : null}
                  </div>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Attachments preview</p>
                  <div className="mt-3 max-h-40 space-y-2 overflow-y-auto pr-1 text-sm text-slate-200">
                    {(preview?.attachments_preview || []).map((item) => (
                      <p key={item.name}>
                        {item.name} ({item.size_bytes} bytes)
                      </p>
                    ))}
                    {!preview?.attachments_preview?.length ? <p className="text-sm text-slate-400">Attachments will appear after preview generation.</p> : null}
                  </div>
                </div>

                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Complaint body preview</p>
                  <pre className="mt-3 max-h-[30rem] overflow-y-auto whitespace-pre-wrap pr-1 text-sm text-slate-200">
                    {preview?.complaint_body || 'Preview content will appear here after generation.'}
                  </pre>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-white/8 bg-[rgba(2,6,23,0.96)] px-6 py-4">
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={handlePreview}
                disabled={previewing}
                className="terminal-text rounded-[18px] bg-[linear-gradient(135deg,#00E5FF,#00FF9F)] px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-slate-950 disabled:opacity-60"
              >
                {previewing ? 'Generating Preview...' : 'Preview Complaint'}
              </button>
              <button
                type="button"
                onClick={handleSend}
                disabled={sendDisabled}
                className="terminal-text rounded-[18px] border border-[#FF3B3B]/30 bg-[#FF3B3B]/10 px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-[#FFD0D0] disabled:opacity-60"
              >
                {sending ? 'Sending...' : status?.live_delivery_ready ? 'Send To Cyber Cell' : 'Live Email Not Ready'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CyberCellReportModal
