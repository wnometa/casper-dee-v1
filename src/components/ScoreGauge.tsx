interface ScoreGaugeProps {
  value: number;
}

export function ScoreGauge({ value }: ScoreGaugeProps) {
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  const color = value >= 75 ? "var(--success)" : value >= 50 ? "var(--medium)" : value >= 25 ? "var(--high)" : "var(--critical)";

  return (
    <div className="score-gauge">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={radius} fill="none" stroke="var(--bg-3)" strokeWidth="10" />
        <circle
          cx="80" cy="80" r={radius} fill="none"
          stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.4s ease" }}
        />
      </svg>
      <div className="score-gauge-value">
        <span className="score-gauge-number" style={{ color }}>{value}</span>
        <span className="score-gauge-label">Posture</span>
      </div>
    </div>
  );
}
