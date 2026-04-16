import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getVerifiedReport, verifyReportUpload } from '../services/api'

function statusClasses(status) {
  if (status === 'VALID') {
    return 'border-[#00FF9F]/35 bg-[#00FF9F]/10 text-[#B8FFE0]'
  }
  if (status === 'EXPIRED') {
    return 'border-[#FFC857]/35 bg-[#FFC857]/10 text-[#FFE4A3]'
  }
  return 'border-[#FF3B3B]/35 bg-[#FF3B3B]/10 text-[#FECACA]'
}

function shorten(value) {
  if (!value) {
    return 'Unavailable'
  }
  if (value.length <= 24) {
    return value
  }
  return `${value.slice(0, 16)}...${value.slice(-8)}`
}

function VerifyReport() {
  const { reportId } = useParams()
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState(null)

  useEffect(() => {
    let active = true
    const loadReport = async () => {
      setLoading(true)
      setError('')
      try {
        const response = await getVerifiedReport(reportId)
        if (active) {
          setReport(response)
        }
      } catch (apiError) {
        if (active) {
          setError(apiError?.response?.data?.detail || 'Unable to load verification details for this report.')
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadReport()
    return () => {
      active = false
    }
  }, [reportId])

  const severityRows = useMemo(
    () => Object.entries(report?.severity_distribution || {}),
    [report],
  )

  const handleUpload = async (event) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }
    setUploading(true)
    setUploadResult(null)
    try {
      const response = await verifyReportUpload(reportId, file)
      setUploadResult(response)
    } catch (apiError) {
      setUploadResult({
        verification_status: 'INVALID',
        message: apiError?.response?.data?.detail || 'PDF verification failed.',
      })
    } finally {
      setUploading(false)
      event.target.value = ''
    }
  }

  return (
    <section className="mx-auto max-w-5xl rounded-[32px] border border-white/10 bg-slate-950/55 p-6 shadow-[0_0_50px_rgba(15,23,42,0.35)] backdrop-blur">
      <div className="flex flex-col gap-4 border-b border-white/8 pb-6">
        <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">CITADEL Verified Reporting Protocol</p>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-semibold text-white">Public report verification</h1>
            <p className="mt-2 text-sm text-slate-300">
              Validate that a CITADEL-issued report matches the stored verification record without exposing internal evidence.
            </p>
          </div>
          <div className={`rounded-full border px-4 py-2 text-xs uppercase tracking-[0.24em] ${statusClasses(uploadResult?.verification_status || report?.verification_status)}`}>
            {uploadResult?.verification_status || report?.verification_status || 'LOADING'}
          </div>
        </div>
      </div>

      {loading ? (
        <div className="py-10 text-sm text-slate-300">Loading verification record...</div>
      ) : error ? (
        <div className="mt-6 rounded-[20px] border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-4 text-sm text-[#FECACA]">
          {error}
        </div>
      ) : (
        <div className="mt-6 space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Report ID</p>
              <p className="mt-2 break-all text-sm text-slate-100">{report.report_id}</p>
            </div>
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Organization</p>
              <p className="mt-2 text-sm text-slate-100">{report.org_name || 'Restricted'}</p>
            </div>
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Generated</p>
              <p className="mt-2 text-sm text-slate-100">{report.generated_at || 'Unavailable'}</p>
            </div>
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Cases</p>
              <p className="mt-2 text-sm text-slate-100">{report.case_count ?? 0}</p>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-5">
              <h2 className="text-lg font-semibold text-white">Verification summary</h2>
              <div className="mt-4 space-y-3 text-sm text-slate-300">
                <p>
                  <span className="font-medium text-slate-100">PDF hash:</span> {shorten(report.pdf_sha256)}
                </p>
                <p>
                  <span className="font-medium text-slate-100">Signature:</span> {shorten(report.signature_base64_masked)}
                </p>
                <p>
                  <span className="font-medium text-slate-100">Key fingerprint:</span> {shorten(report.public_key_fingerprint)}
                </p>
                <p>
                  <span className="font-medium text-slate-100">Expiry:</span> {report.expires_at || 'No expiry'}
                </p>
                <p>
                  <span className="font-medium text-slate-100">Evidence summary:</span>{' '}
                  {report.evidence_summary?.summary || 'Metadata summary only'}
                </p>
              </div>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-5">
              <h2 className="text-lg font-semibold text-white">Severity distribution</h2>
              <div className="mt-4 space-y-2">
                {severityRows.length ? (
                  severityRows.map(([label, count]) => (
                    <div key={label} className="flex items-center justify-between rounded-[16px] border border-white/8 bg-white/5 px-3 py-2 text-sm text-slate-200">
                      <span>{label}</span>
                      <span>{count}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-slate-400">No public severity summary is available.</p>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-[22px] border border-white/8 bg-black/10 p-5">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Upload PDF to verify</h2>
                <p className="mt-2 text-sm text-slate-300">
                  Upload the received PDF to confirm the document hash matches the stored CVRP record.
                </p>
              </div>
              <label className="inline-flex cursor-pointer items-center rounded-[18px] border border-[#00E5FF]/35 bg-[#00E5FF]/10 px-4 py-3 text-sm text-[#CFFAFE]">
                <input type="file" accept="application/pdf" className="hidden" onChange={handleUpload} />
                {uploading ? 'Verifying...' : 'Upload PDF to Verify'}
              </label>
            </div>

            {uploadResult ? (
              <div className={`mt-4 rounded-[18px] border px-4 py-4 text-sm ${statusClasses(uploadResult.verification_status)}`}>
                <p className="font-medium">
                  {uploadResult.verification_status === 'VALID'
                    ? 'Verified authentic CITADEL report.'
                    : uploadResult.verification_status === 'EXPIRED'
                      ? 'Report record exists but has expired.'
                      : 'Report mismatch or possible tampering detected.'}
                </p>
                <p className="mt-2">{uploadResult.message}</p>
                {uploadResult.uploaded_pdf_sha256 ? (
                  <p className="mt-2 break-all text-xs">
                    Uploaded hash: {uploadResult.uploaded_pdf_sha256}
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </section>
  )
}

export default VerifyReport
