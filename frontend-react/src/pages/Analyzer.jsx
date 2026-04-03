import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import Loader from '../components/Loader'
import ThreatCard from '../components/ThreatCard'
import RiskBadge from '../components/RiskBadge'
import { analyzeText } from '../services/api'

const sampleTexts = [
  'Admin login credentials for SBI with email ops@sbi.com password=Root@123 and hidden access panel.',
  'Ransomware toolkit for sale with crypter, loader and persistence support.',
  'Phishing page ready for Microsoft 365 users with OTP relay and Telegram operator.',
]

function useTypedText(value) {
  const [displayText, setDisplayText] = useState('')

  useEffect(() => {
    if (!value) {
      return
    }

    let index = 0
    const interval = window.setInterval(() => {
      index += 1
      setDisplayText(value.slice(0, index))
      if (index >= value.length) {
        window.clearInterval(interval)
      }
    }, 15)

    return () => window.clearInterval(interval)
  }, [value])

  return displayText
}

function Analyzer() {
  const [text, setText] = useState(sampleTexts[0])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const summaryText = useMemo(() => {
    if (!result) {
      return ''
    }

    return `Threat ${result.threat_type} detected with ${result.risk_level} risk and ${(result.confidence_score * 100).toFixed(1)} percent confidence.`
  }, [result])

  const typedSummary = useTypedText(summaryText)

  const handleAnalyze = async () => {
    if (!text.trim()) {
      setError('Enter suspicious content before running analysis.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await analyzeText(text.trim())
      setResult(response)
    } catch (apiError) {
      setError(
        apiError?.response?.data?.detail ||
          'Backend is unreachable. Start the FastAPI server at http://127.0.0.1:8000.',
      )
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
      <Motion.section
        initial={{ opacity: 0, x: -18 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card rounded-3xl p-6"
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00CFFF]">Analyzer</p>
            <h2 className="mt-2 text-3xl font-semibold text-white">Investigate suspicious dark web chatter</h2>
          </div>
          <RiskBadge level={result?.risk_level || 'LOW'} />
        </div>

        <p className="mt-4 max-w-2xl text-sm text-slate-300">
          Submit leaked credentials, phishing lures, malware sale chatter, or database dump references for
          instant AI-assisted triage.
        </p>

        <div className="mt-6 space-y-4">
          <textarea
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Paste suspicious text, forum snippet, or credential sale post..."
            className="min-h-64 w-full rounded-3xl border border-[#00CFFF]/20 bg-[#020817]/80 p-4 text-sm text-slate-100 outline-none transition focus:border-[#00CFFF] focus:shadow-[0_0_18px_rgba(0,207,255,0.2)]"
          />

          <div className="flex flex-wrap gap-3">
            {sampleTexts.map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => setText(sample)}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs text-slate-300 transition hover:border-[#00CFFF]/35 hover:text-white"
              >
                Load sample
              </button>
            ))}
          </div>

          <Motion.button
            whileTap={{ scale: 0.98 }}
            whileHover={{ y: -1 }}
            type="button"
            onClick={handleAnalyze}
            className="inline-flex items-center justify-center rounded-2xl bg-[#00CFFF] px-5 py-3 font-semibold text-slate-950 shadow-[0_0_24px_rgba(0,207,255,0.35)] transition hover:bg-[#60dfff]"
          >
            Analyze Threat
          </Motion.button>

          {error && (
            <div className="rounded-2xl border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-3 text-sm text-[#FFB4B4]">
              {error}
            </div>
          )}
        </div>
      </Motion.section>

      <Motion.section
        initial={{ opacity: 0, x: 18 }}
        animate={{ opacity: 1, x: 0 }}
        className="space-y-6"
      >
        <div className="glass-card rounded-3xl p-6">
          <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">AI Output</p>
          <h3 className="mt-2 text-2xl font-semibold text-white">Threat verdict</h3>
          <div className="mt-6 min-h-28 rounded-2xl border border-white/8 bg-black/10 p-4">
            {loading ? (
              <Loader label="Running regex, NLP, and model inference..." />
            ) : typedSummary ? (
              <p className="text-lg leading-8 text-slate-100">{typedSummary}</p>
            ) : (
              <p className="text-slate-400">Run an analysis to see threat classification, extracted entities, and risk signals.</p>
            )}
          </div>
        </div>

        {result && <ThreatCard item={result} />}
      </Motion.section>
    </div>
  )
}

export default Analyzer
