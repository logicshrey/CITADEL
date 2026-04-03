import { useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import Loader from '../components/Loader'
import RiskBadge from '../components/RiskBadge'
import StatCard from '../components/StatCard'
import Toast from '../components/Toast'
import UploadBox from '../components/UploadBox'
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
  const [toast, setToast] = useState('')
  const [loading, setLoading] = useState(false)
  const [fileName, setFileName] = useState('')

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
      setFileName(file.name)
      setResults([])
      setToast('')
      setStatus(`Loaded ${parsedRows.length} rows from ${file.name}.`)
    } catch {
      setToast('Unable to read the CSV file. Please upload a valid UTF-8 CSV.')
    }
  }

  const handleAnalyzeUpload = async () => {
    if (!rows.length || !selectedColumn) {
      setToast('Upload a CSV file and select a text column first.')
      return
    }

    setLoading(true)
    setToast('')
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
      setToast(
        apiError?.response?.data?.detail ||
          'Backend upload workflow failed. Start FastAPI and try again.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <Toast message={toast} tone={status && !toast ? 'success' : 'error'} />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Rows Loaded" value={rows.length} accent="#00E5FF" icon="RL" />
        <StatCard label="Rows Analyzed" value={results.length} accent="#00FF9F" icon="RA" />
        <StatCard label="Selected Column" value={selectedColumn || '--'} accent="#FFC857" icon="SC" />
        <StatCard label="Upload Mode" value="API" accent="#FF3B3B" icon="UP" />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <Motion.section
          initial={{ opacity: 0, x: -16 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <div className="glass-card neon-panel rounded-[32px] p-6">
            <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Upload Bay</p>
            <h2 className="mt-2 text-4xl font-semibold text-white">Ingest external intelligence datasets</h2>
            <p className="mt-4 text-sm text-slate-300">
              Drag in CSV exports and route the most relevant rows through the existing backend analysis API without altering server-side behavior.
            </p>

            <div className="mt-6">
              <UploadBox onChange={handleFileChange} fileName={fileName} rowCount={rows.length} />
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-[1fr_auto]">
              <div>
                <label className="mb-2 block text-sm text-slate-300">Text column</label>
                <select
                  value={selectedColumn}
                  onChange={(event) => setSelectedColumn(event.target.value)}
                  className="w-full rounded-[20px] border border-white/10 bg-[#020817]/80 px-4 py-3 text-slate-100 outline-none focus:border-[#00E5FF]"
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
                className="terminal-text self-end rounded-[22px] bg-[linear-gradient(135deg,#00FF9F,#00E5FF)] px-5 py-3 text-sm font-bold uppercase tracking-[0.28em] text-slate-950 shadow-[0_0_24px_rgba(0,255,159,0.24)] transition"
              >
                Analyze Upload
              </Motion.button>
            </div>

            {status ? (
              <div className="mt-4 rounded-[22px] border border-[#00FF9F]/30 bg-[#00FF9F]/10 px-4 py-3 text-sm text-[#B8FFE3]">
                {status}
              </div>
            ) : null}
          </div>
        </Motion.section>

        <Motion.section
          initial={{ opacity: 0, x: 16 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <div className="glass-card neon-panel rounded-[32px] p-6">
            <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">File Requirements</p>
            <ul className="mt-4 space-y-3 text-sm text-slate-300">
              <li>• Upload UTF-8 CSV files only</li>
              <li>• Include a text-bearing column such as `text`, `message`, or `description`</li>
              <li>• Current client-side batch limit is 25 rows per run</li>
              <li>• Analysis is routed through the existing `POST /analyze` endpoint</li>
            </ul>
          </div>

          <div className="glass-card neon-panel rounded-[32px] p-6">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Upload Results</p>
                <h3 className="mt-2 text-2xl font-semibold text-white">Batch summary</h3>
              </div>
              {results.length > 0 ? <div className="text-sm text-slate-400">{results.length} rows analyzed</div> : null}
            </div>

            {loading ? (
              <Loader label="Analyzing uploaded rows through the API..." />
            ) : results.length === 0 ? (
              <div className="rounded-[24px] border border-white/8 bg-black/10 px-4 py-10 text-center text-slate-400">
                No upload results yet. Choose a CSV file and run batch analysis.
              </div>
            ) : (
              <div className="space-y-3">
                {results.map((item) => (
                  <div
                    key={`${item.source}-${item.threat_type}`}
                    className="rounded-[22px] border border-white/8 bg-black/10 p-4"
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="max-w-xl">
                        <p className="line-clamp-2 text-sm text-slate-200">{item.source}</p>
                        <p className="mt-2 text-xs uppercase tracking-[0.3em] text-[#00E5FF]">{item.threat_type}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <RiskBadge level={item.risk_level} />
                        <span className="terminal-text text-sm text-slate-400">{(item.confidence_score * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Motion.section>
      </div>
    </div>
  )
}

export default Upload
