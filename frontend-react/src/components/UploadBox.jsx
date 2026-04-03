import { motion as Motion } from 'framer-motion'

function UploadBox({ onChange, fileName, rowCount }) {
  return (
    <Motion.label
      whileHover={{ y: -3, scale: 1.01 }}
      className="glass-card neon-panel flex cursor-pointer flex-col items-center justify-center rounded-[30px] border border-dashed border-[#00E5FF]/35 bg-[#020617]/65 px-6 py-14 text-center"
    >
      <div className="flex h-[4.5rem] w-[4.5rem] items-center justify-center rounded-full border border-[#00E5FF]/30 bg-[#00E5FF]/10 text-3xl text-[#00E5FF] shadow-[0_0_22px_rgba(0,229,255,0.14)]">
        ↑
      </div>
      <h3 className="mt-6 text-2xl font-semibold text-white">Drop intelligence CSV here</h3>
      <p className="mt-3 max-w-md text-sm text-slate-400">
        Supports drag-and-drop style upload for exported feeds, marketplace scrapes, or analyst-prepared CSV data.
      </p>
      <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-xs uppercase tracking-[0.28em] text-slate-400">
        <span className="rounded-full border border-white/10 px-3 py-1">csv only</span>
        <span className="rounded-full border border-white/10 px-3 py-1">{fileName || 'no file selected'}</span>
        <span className="rounded-full border border-white/10 px-3 py-1">{rowCount} rows</span>
      </div>
      <input type="file" accept=".csv" className="hidden" onChange={onChange} />
    </Motion.label>
  )
}

export default UploadBox
