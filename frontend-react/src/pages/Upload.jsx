import { useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import Loader from '../components/Loader'
import RiskBadge from '../components/RiskBadge'
import { analyzeText } from '../services/api'

function parseCsvRow(row) {
  const values = []
  let current = ''
  let inQuotes = false

  for (let index = 0; index < row.length; index += 1) {
    const char = row[index]
    const nextChar = row[index + 1]

    if (char === '"' && nextChar === '"') {
      current += '"'
      index += 1
      continue
    }

    if (char === '"') {
      inQuotes = !inQuotes
      continue
    }

    if (char === ',' && !inQuotes) {
      values.push(current)
      current = ''
      continue
    }

    current += char
  }

  values.push(current)
  return values.map((value) => value.trim())
}

function parseCsvText(text) {
  const rows = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)

  if (rows.length === 0) {
    return []
  }

  const headers = parseCsvRow(rows[0])
  return rows.slice(1).map((row) => {
    const values = parseCsvRow(row)
    return headers.reduce((accumulator, header, index) => {
      accumulator[header] = values[index] ?? ''
      return accumulator
    }, {})
  })
}

function Upload() {
  const [rows, setRows] = useState([])
  const [selectedColumn, setSelectedColumn] = useState('')
  const [results, setResults] = useState([])
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const columns = useMemo(() => (rows[0] ? Object.keys(rows[0]) : []), [rows])

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    try {
      const text = await file.text()
      const parsedRows = parseCsvText(text)
      setRows(parsedRows)
      setSelectedColumn(parsedRows[0] ? Object.keys(parsedRows[0])[0] : '')
      setResults([])
      setError('')
      setStatus(`Loaded ${parsedRows.length} rows from ${file.name}.`)
    } catch {
      setError('Unable to read the CSV file. Please upload a valid UTF-8 CSV.')
    }
  }

  const handleAnalyzeUpload = async () => {
    if (!rows.length || !selectedColumn) {
      setError('Upload a CSV file and select a text column first.')
      return
    }

    setLoading(true)
    setError('')
    setStatus('')

    try {
      const subset = rows.filter((row) => row[selectedColumn]).slice(0, 25)
      const analyses = []
      for (const row of subset) {
        const response = await analyzeText(row[selectedColumn])
        analyses.push({
          source: row[selectedColumn],
          threat_type: response.threat_type,
          risk_level: response.risk_level,
          confidence_score: response.confidence_score,
        })
      }
      setResults(analyses)
      setStatus(`Successfully analyzed ${analyses.length} rows through the existing /analyze API.`)
    } catch (apiError) {
      setError(
        apiError?.response?.data?.detail ||
          'Backend upload workflow failed. Start FastAPI and try again.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <Motion.section
        initial={{ opacity: 0, x: -16 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card rounded-3xl p-6"
      >
        <p className="text-xs uppercase tracking-[0.35em] text-[#00CFFF]">CSV Upload</p>
        <h2 className="mt-2 text-3xl font-semibold text-white">Batch triage suspicious records</h2>
        <p className="mt-4 text-sm text-slate-300">
          This page uses the existing API only. If a dedicated upload endpoint is unavailable, it falls back to
          sending each row through `/analyze`.
        </p>

        <div className="mt-6 space-y-4">
          <label className="flex cursor-pointer flex-col items-center justify-center rounded-3xl border border-dashed border-[#00CFFF]/35 bg-[#020817]/70 px-6 py-10 text-center transition hover:border-[#00CFFF]">
            <span className="text-lg font-medium text-white">Drop a CSV file here or click to browse</span>
            <span className="mt-2 text-sm text-slate-400">Supports files with a text-like column such as `text` or `message`.</span>
            <input type="file" accept=".csv" className="hidden" onChange={handleFileChange} />
          </label>

          <div>
            <label className="mb-2 block text-sm text-slate-300">Text column</label>
            <select
              value={selectedColumn}
              onChange={(event) => setSelectedColumn(event.target.value)}
              className="w-full rounded-2xl border border-white/10 bg-[#020817]/80 px-4 py-3 text-slate-100 outline-none focus:border-[#00CFFF]"
            >
              {columns.length === 0 ? <option value="">No columns detected</option> : null}
              {columns.map((column) => (
                <option key={column} value={column}>
                  {column}
                </option>
              ))}
            </select>
          </div>

          <Motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.98 }}
            type="button"
            onClick={handleAnalyzeUpload}
            className="rounded-2xl bg-[#00FF9F] px-5 py-3 font-semibold text-slate-950 shadow-[0_0_24px_rgba(0,255,159,0.28)] transition hover:bg-[#6fffc9]"
          >
            Analyze Uploaded Rows
          </Motion.button>

          {status && <div className="rounded-2xl border border-[#00FF9F]/30 bg-[#00FF9F]/10 px-4 py-3 text-sm text-[#B8FFE3]">{status}</div>}
          {error && <div className="rounded-2xl border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-3 text-sm text-[#FFB4B4]">{error}</div>}
        </div>
      </Motion.section>

      <Motion.section
        initial={{ opacity: 0, x: 16 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card rounded-3xl p-6"
      >
        <div className="mb-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Upload Results</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">Batch analysis summary</h3>
          </div>
          {results.length > 0 && <div className="text-sm text-slate-400">{results.length} rows analyzed</div>}
        </div>

        {loading ? (
          <Loader label="Analyzing uploaded rows through the API..." />
        ) : results.length === 0 ? (
          <div className="rounded-2xl border border-white/8 bg-black/10 px-4 py-10 text-center text-slate-400">
            No upload results yet. Choose a CSV file and run batch analysis.
          </div>
        ) : (
          <div className="space-y-3">
            {results.map((item) => (
              <div
                key={`${item.source}-${item.threat_type}`}
                className="rounded-2xl border border-white/8 bg-black/10 p-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="max-w-xl">
                    <p className="line-clamp-2 text-sm text-slate-200">{item.source}</p>
                    <p className="mt-2 text-xs uppercase tracking-[0.3em] text-[#00CFFF]">{item.threat_type}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <RiskBadge level={item.risk_level} />
                    <span className="text-sm text-slate-400">{(item.confidence_score * 100).toFixed(1)}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Motion.section>
    </div>
  )
}

export default Upload
