const riskStyles = {
  HIGH: 'border-[#FF3B3B]/60 bg-[#FF3B3B]/12 text-[#FF6B6B] shadow-[0_0_18px_rgba(255,59,59,0.25)]',
  MEDIUM:
    'border-[#FFC857]/50 bg-[#FFC857]/10 text-[#FFD98C] shadow-[0_0_18px_rgba(255,200,87,0.16)]',
  LOW: 'border-[#00FF9F]/55 bg-[#00FF9F]/10 text-[#00FF9F] shadow-[0_0_18px_rgba(0,255,159,0.2)]',
}

function RiskBadge({ level = 'LOW', className = '' }) {
  const normalizedLevel = String(level || 'LOW').toUpperCase()
  const colorClasses = riskStyles[normalizedLevel] || riskStyles.LOW

  return (
    <span
      className={`terminal-text inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.28em] ${colorClasses} ${className}`}
    >
      {normalizedLevel}
    </span>
  )
}

export default RiskBadge
