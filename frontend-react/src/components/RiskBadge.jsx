const riskStyles = {
  HIGH: 'border-[#FF3B3B]/60 bg-[#FF3B3B]/12 text-[#FF6B6B] shadow-[0_0_18px_rgba(255,59,59,0.25)]',
  MEDIUM:
    'border-yellow-400/50 bg-yellow-400/10 text-yellow-300 shadow-[0_0_18px_rgba(250,204,21,0.16)]',
  LOW: 'border-[#00FF9F]/55 bg-[#00FF9F]/10 text-[#00FF9F] shadow-[0_0_18px_rgba(0,255,159,0.2)]',
}

function RiskBadge({ level = 'LOW', className = '' }) {
  const normalizedLevel = String(level || 'LOW').toUpperCase()
  const colorClasses = riskStyles[normalizedLevel] || riskStyles.LOW

  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold tracking-[0.28em] ${colorClasses} ${className}`}
    >
      {normalizedLevel}
    </span>
  )
}

export default RiskBadge
