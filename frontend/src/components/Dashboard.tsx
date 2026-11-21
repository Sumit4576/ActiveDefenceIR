import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'

/* ════════════════════════════════════════════════
   MOCK DATA POOLS
   ════════════════════════════════════════════════ */
const IPS = [
  '198.51.100.22', '203.0.113.45', '192.168.1.15',
  '10.0.0.5', '172.16.254.1', '104.18.23.44',
  '45.33.32.156', '91.189.88.142', '185.220.101.1',
]
const COUNTRIES = ['US', 'RU', 'CN', 'DE', 'BR', 'IN', 'IR', 'KR']
const PATHS = ['/api/login', '/wp-admin', '/.env', '/etc/passwd', '/graphql', '/admin/config', '/api/users']
const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
const ATTACK_TYPES = ['SQL_INJECTION', 'XSS', 'DIR_TRAVERSAL', 'BRUTE_FORCE', 'CMD_INJECTION', 'UNKNOWN']

const CONTAINER_IMAGES = ['web-honeypot', 'cowrie-ssh', 'dionaea', 'elasticpot', 'mailoney']

const AGENT_LINES: [string, string][] = [
  ['Cipher', 'Tracing anomaly origin to 203.0.113.45...'],
  ['Cipher', 'Detected anomalous payload structure in POST /api/login.'],
  ['Cipher', 'Anomaly score spiked to -0.1852 on endpoint /wp-admin.'],
  ['Cipher', 'Cross-referencing source IP against known threat feeds.'],
  ['Cipher', 'Network flow analysis: 14 packets, avg size 412B.'],
  ['Aegis', 'Honeypot deployed successfully on port 9042.'],
  ['Aegis', 'Captured XSS payload: <script>document.cookie</script>'],
  ['Aegis', "Captured SQLi payload: ' OR 1=1; DROP TABLE users --"],
  ['Aegis', 'Extracting user-agent fingerprint: sqlmap/1.7.'],
  ['Aegis', 'Payload entropy: 4.82 bits/byte — likely encoded.'],
  ['Oracle', 'Synthesizing findings from Cipher and Aegis.'],
  ['Oracle', 'TTPs align with MITRE ATT&CK T1190 (Exploit Public App).'],
  ['Oracle', 'Confidence: HIGH. Recommend immediate IP block.'],
  ['Oracle', 'Generating executive threat intelligence report...'],
  ['Oracle', 'Report ready. Classification: CRITICAL.'],
]

const REPORTS = [
  `# Threat Intelligence Report
**Generated:** ${new Date().toISOString()}
**Classification:** CRITICAL
**Investigation ID:** INV-20260712-A1B2

## Executive Summary
The ActiveDefenceIR system detected **23 anomaly alerts** across the monitoring window. The Isolation Forest flagged SQL injection, XSS, and directory traversal attempts originating from **3 unique source IPs**. The deception grid deployed **12 honeypot instances**, capturing **165 malicious payloads**.

## Attacker Profile
| Attribute | Details |
|-----------|---------|
| Primary IPs | \`203.0.113.45\`, \`198.51.100.22\` |
| Attack Vectors | SQL Injection, XSS, Path Traversal |
| Tooling | sqlmap/1.7, Python-urllib |
| Sophistication | Medium (automated scripting) |

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Credential Access | Brute Force | T1110 |

## Recommended Actions
1. **Immediate:** Block \`203.0.113.45\` and \`198.51.100.22\` at perimeter firewall.
2. **Short-term:** Deploy WAF rules for detected SQLi and XSS signatures.
3. **Long-term:** Implement MFA on all authentication endpoints.`,

  `# Threat Intelligence Report
**Generated:** ${new Date().toISOString()}
**Classification:** HIGH
**Investigation ID:** INV-20260712-C3D4

## Executive Summary
Secondary wave of reconnaissance detected. Nmap scripting engine probes targeting SSH and HTTP services. Cowrie honeypot captured **42 credential stuffing attempts** using leaked password lists.

## Attacker Profile
| Attribute | Details |
|-----------|---------|
| Primary IPs | \`45.33.32.156\`, \`185.220.101.1\` |
| Attack Vectors | Credential Stuffing, Service Enumeration |
| Tooling | Nmap NSE, Hydra |

## Recommended Actions
1. Enable account lockout after 5 failed attempts.
2. Review SSH key-based authentication enforcement.
3. Update Cowrie honeypot interaction profiles.`,
]

const TICKER_ITEMS = [
  'NEW IP RANGE 203.0.113.0/24 ADDED TO THREAT FEED',
  'HONEYPOT-2A1B CAPTURED MIRAI VARIANT PAYLOAD',
  'ISOLATION FOREST THRESHOLD AUTO-TUNED TO -0.152',
  'COWRIE SSH HONEYPOT LOGGED 42 CREDENTIAL ATTEMPTS',
  'AGENT ORACLE CONFIDENCE LEVEL: 94.2%',
  'WAF RULE UPDATE DEPLOYED FOR SQLI SIGNATURES',
  'TOR EXIT NODE 185.220.101.1 FLAGGED',
]

/* ════════════════════════════════════════════════
   HELPER: pick random from array
   ════════════════════════════════════════════════ */
function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

/* ════════════════════════════════════════════════
   SUB-COMPONENTS
   ════════════════════════════════════════════════ */

interface Alert {
  id: string
  time: string
  ip: string
  country: string
  method: string
  path: string
  type: string
  score: number
}

interface Honeypot {
  status: 'idle' | 'deploying' | 'active' | 'captured'
  image: string
  ip: string | null
  port: number | null
}

/* ── Header ── */
function HeaderBar({ stats, time, wsConnected }: { stats: { requests: number; threats: number }; time: Date; wsConnected: boolean }) {
  const utc = time.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  return (
    <header className="panel flex-row! items-center justify-between px-5 py-3">
      <div className="flex items-center gap-3">
        <div className="w-3 h-3 rounded-full bg-[var(--color-cyber-red)] anim-glowPulse" />
        <div>
          <h1 className="text-lg font-bold text-[var(--color-neon-cyan)] tracking-[0.15em] uppercase leading-tight">
            ActiveDefenceIR
          </h1>
          <p className="text-[0.65rem] text-slate-500 mono tracking-widest">AUTONOMOUS DECEPTION &amp; AI INVESTIGATION</p>
        </div>
        <div className={'ml-3 flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[0.6rem] mono ' + (wsConnected ? 'bg-green-900/30 text-green-400 border border-green-500/30' : 'bg-slate-800/50 text-slate-500 border border-slate-700/30')}>
          <div className={'w-1.5 h-1.5 rounded-full ' + (wsConnected ? 'bg-green-400 anim-pulseDot' : 'bg-slate-600')} />
          {wsConnected ? 'LIVE DATA' : 'DEMO MODE'}
        </div>
      </div>
      <div className="flex gap-8 mono text-xs">
        <div className="flex flex-col items-center">
          <span className="text-slate-500 text-[0.6rem]">REQUESTS</span>
          <span className="text-[var(--color-cyber-green)] text-sm font-bold">{stats.requests.toLocaleString()}</span>
        </div>
        <div className="flex flex-col items-center">
          <span className="text-slate-500 text-[0.6rem]">THREATS</span>
          <span className="text-[var(--color-cyber-red)] text-sm font-bold">{stats.threats}</span>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-slate-500 text-[0.6rem]">SYSTEM TIME</span>
          <span className="text-[var(--color-neon-cyan)] text-sm">{utc}</span>
        </div>
      </div>
    </header>
  )
}

/* ── Score Bar ── */
function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.abs(score) * 400)
  const danger = score < -0.15
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <span className={danger ? 'text-[var(--color-cyber-red)]' : 'text-[var(--color-cyber-amber)]'}>
        {score.toFixed(4)}
      </span>
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{
            width: pct + '%',
            background: danger
              ? 'linear-gradient(90deg, #ff003c, #ff6b6b)'
              : 'linear-gradient(90deg, #ffb300, #ffd54f)',
            boxShadow: danger ? '0 0 8px rgba(255,0,60,0.6)' : undefined,
          }}
        />
      </div>
    </div>
  )
}

/* ── Threat Stream ── */
function ThreatStream({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="panel flex-1 min-h-0">
      <div className="panel-head">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
        Live Threat Stream
        <span className="ml-auto chip bg-red-900/40 text-[var(--color-cyber-red)] border border-red-500/30">LIVE</span>
      </div>
      <div className="flex-1 overflow-auto p-3 relative">
        <div className="scan-line absolute inset-0 pointer-events-none z-10" />
        <table className="w-full text-left mono text-xs relative z-0">
          <thead>
            <tr className="text-slate-500 border-b border-[var(--color-panel-border)]">
              <th className="pb-2 pr-2">TIME</th>
              <th className="pb-2 pr-2">SOURCE</th>
              <th className="pb-2 pr-2">METHOD</th>
              <th className="pb-2 pr-2">TARGET</th>
              <th className="pb-2 pr-2">TYPE</th>
              <th className="pb-2">SCORE</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id} className="border-b border-white/5 anim-fadeInUp">
                <td className="py-1.5 pr-2 text-slate-500">{a.time}</td>
                <td className="py-1.5 pr-2 text-[var(--color-neon-cyan)]">
                  {a.ip} <span className="text-slate-600 text-[0.6rem]">{a.country}</span>
                </td>
                <td className="py-1.5 pr-2 text-slate-400">{a.method}</td>
                <td className="py-1.5 pr-2 text-slate-300">{a.path}</td>
                <td className="py-1.5 pr-2">
                  <span className="chip bg-red-900/30 text-red-400 border border-red-500/20">{a.type}</span>
                </td>
                <td className="py-1.5"><ScoreBar score={a.score} /></td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr><td colSpan={6} className="py-6 text-center text-slate-600">Awaiting traffic data...</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── Deception Grid ── */
function DeceptionGrid({ honeypots }: { honeypots: Honeypot[] }) {
  const statusColors: Record<string, string> = {
    idle: 'border-slate-700/50 bg-slate-900/30 text-slate-600',
    deploying: 'border-amber-500/40 bg-amber-950/20 text-amber-400',
    active: 'border-green-500/40 bg-green-950/20 text-green-400',
    captured: 'border-red-500/60 bg-red-950/30 text-red-400 anim-pulseDot',
  }
  const statusIcons: Record<string, string> = {
    idle: 'M20 12H4', // line
    deploying: 'M12 2v20M2 12h20', // plus
    active: 'M5 13l4 4L19 7', // check
    captured: 'M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z', // alert
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" /></svg>
        Deception Grid
        <span className="ml-auto text-[0.6rem] text-slate-500">{honeypots.filter(h => h.status !== 'idle').length} / {honeypots.length} active</span>
      </div>
      <div className="p-3 grid grid-cols-4 sm:grid-cols-6 gap-2">
        {honeypots.map((h, i) => (
          <div
            key={i}
            className={'border rounded-lg p-2 flex flex-col items-center justify-center gap-1 transition-all duration-500 min-h-[72px] ' + statusColors[h.status]}
          >
            <svg className={'w-5 h-5 ' + (h.status === 'deploying' ? 'anim-spinSlow' : '')} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={statusIcons[h.status]} />
            </svg>
            <span className="text-[0.55rem] uppercase tracking-widest">{h.status}</span>
            {h.image && <span className="text-[0.5rem] opacity-60">{h.image}</span>}
            {h.port && <span className="text-[0.5rem] opacity-50">:{h.port}</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Agent Console ── */
function AgentConsole({ logs }: { logs: string[] }) {
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])

  const agentColor = (line: string) => {
    if (line.includes('[Cipher]')) return 'text-[var(--color-neon-cyan)]'
    if (line.includes('[Aegis]')) return 'text-[var(--color-cyber-amber)]'
    if (line.includes('[Oracle]')) return 'text-[var(--color-cyber-green)]'
    return 'text-slate-400'
  }

  return (
    <div className="panel flex-1 min-h-0">
      <div className="panel-head">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
        AI Analyst Console
      </div>
      <div className="flex gap-3 px-3 pt-2 pb-1 border-b border-white/5">
        <span className="text-[0.6rem] mono text-[var(--color-neon-cyan)]">● Cipher</span>
        <span className="text-[0.6rem] mono text-[var(--color-cyber-amber)]">● Aegis</span>
        <span className="text-[0.6rem] mono text-[var(--color-cyber-green)]">● Oracle</span>
      </div>
      <div className="flex-1 overflow-y-auto p-3 mono text-[0.7rem] leading-relaxed space-y-0.5">
        {logs.map((line, i) => (
          <div key={i} className={agentColor(line) + ' anim-fadeInUp'}>{line}</div>
        ))}
        {logs.length === 0 && <div className="text-slate-600">Agents initializing...</div>}
        <div ref={endRef} />
      </div>
    </div>
  )
}

/* ── Report Viewer ── */
function ReportViewer({ report }: { report: string }) {
  const reportRef = useRef<HTMLDivElement>(null)
  const [downloading, setDownloading] = useState(false)

  const handleDownload = async () => {
    if (!reportRef.current || downloading) return
    setDownloading(true)
    try {
      const html2pdf = (await import('html2pdf.js')).default
      const el = reportRef.current
      const opt = {
        margin: [12, 12, 12, 12],
        filename: 'ActiveDefenceIR_Threat_Report_' + new Date().toISOString().slice(0, 10) + '.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, backgroundColor: '#0a0e14', useCORS: true },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' as const },
      }
      await html2pdf().set(opt).from(el).save()
    } catch (e) {
      console.error('PDF generation failed:', e)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="panel flex-1 min-h-0">
      <div className="panel-head bg-linear-to-r from-[rgba(224,64,251,0.1)] to-transparent text-[var(--color-cyber-magenta)] border-b-[var(--color-cyber-magenta)]/20">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
        Threat Intelligence Report
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-[var(--color-cyber-magenta)]/30 bg-[var(--color-cyber-magenta)]/10 text-[var(--color-cyber-magenta)] text-[0.65rem] mono tracking-wider uppercase cursor-pointer transition-all duration-200 hover:bg-[var(--color-cyber-magenta)]/25 hover:border-[var(--color-cyber-magenta)]/60 hover:shadow-[0_0_12px_rgba(224,64,251,0.3)] disabled:opacity-40 disabled:cursor-wait"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            {downloading ? 'Generating...' : 'Download PDF'}
          </button>
          <span className="chip bg-emerald-900/30 text-emerald-400 border border-emerald-500/20">ORACLE</span>
        </div>
      </div>
      <div ref={reportRef} className="flex-1 overflow-y-auto p-4 report-md text-sm">
        <ReactMarkdown>{report}</ReactMarkdown>
      </div>
    </div>
  )
}

/* ── Ticker Bar ── */
function TickerBar() {
  const text = TICKER_ITEMS.join('  ///  ')
  return (
    <div className="panel flex-row! items-center px-0 py-1.5 bg-black/60 overflow-hidden">
      <div className="text-[var(--color-neon-cyan)] mono text-[0.65rem] font-bold px-3 border-r border-slate-700/50 whitespace-nowrap shrink-0">
        LIVE INTEL //
      </div>
      <div className="overflow-hidden flex-1 relative h-4">
        <div className="absolute whitespace-nowrap mono text-[0.65rem] text-slate-400 anim-ticker">
          {text}  ///  {text}
        </div>
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════
   MAIN DASHBOARD
   ════════════════════════════════════════════════ */
export default function Dashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [honeypots, setHoneypots] = useState<Honeypot[]>(
    () => Array.from({ length: 12 }, () => ({ status: 'idle' as const, image: pick(CONTAINER_IMAGES), ip: null, port: null }))
  )
  const [agentLogs, setAgentLogs] = useState<string[]>([])
  const [report, setReport] = useState(REPORTS[0])
  const [, setReportIdx] = useState(0)
  const [stats, setStats] = useState({ requests: 45023, threats: 0 })
  const [time, setTime] = useState(new Date())

  // ── WebSocket + mock fallback ──
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const mockTimersRef = useRef<ReturnType<typeof setInterval>[]>([])
  const [wsConnected, setWsConnected] = useState(false)

  // Start mock timers (fallback when WS is not connected)
  const startMockTimers = useCallback(() => {
    // Clear any existing mock timers first
    mockTimersRef.current.forEach(clearInterval)
    mockTimersRef.current = []

    const alertTimer = setInterval(() => {
      const ts = new Date().toISOString().substring(11, 19)
      const newAlert: Alert = {
        id: Math.random().toString(36).substring(2, 8),
        time: ts,
        ip: pick(IPS),
        country: pick(COUNTRIES),
        method: pick(METHODS),
        path: pick(PATHS),
        type: pick(ATTACK_TYPES),
        score: -(Math.random() * 0.3),
      }
      setAlerts(prev => [newAlert, ...prev].slice(0, 10))
      setStats(prev => ({
        requests: prev.requests + Math.floor(Math.random() * 40) + 5,
        threats: prev.threats + 1,
      }))
    }, 1400)

    const hpTimer = setInterval(() => {
      setHoneypots(prev => {
        const next = [...prev]
        const idx = Math.floor(Math.random() * 12)
        const order: Honeypot['status'][] = ['idle', 'deploying', 'active', 'captured']
        const cur = order.indexOf(next[idx].status)
        const nextStatus = order[(cur + 1) % order.length]
        next[idx] = {
          status: nextStatus,
          image: nextStatus === 'idle' ? pick(CONTAINER_IMAGES) : next[idx].image,
          ip: nextStatus !== 'idle' ? pick(IPS) : null,
          port: nextStatus !== 'idle' ? 9000 + Math.floor(Math.random() * 100) : null,
        }
        return next
      })
    }, 1600)

    const agentTimer = setInterval(() => {
      const [agent, msg] = pick(AGENT_LINES)
      const ts = new Date().toISOString().substring(11, 19)
      setAgentLogs(prev => [...prev, '[' + ts + '] [' + agent + '] ' + msg].slice(-25))
    }, 900)

    const reportTimer = setInterval(() => {
      setReportIdx(prev => {
        const next = (prev + 1) % REPORTS.length
        setReport(REPORTS[next])
        return next
      })
    }, 18000)

    mockTimersRef.current = [alertTimer, hpTimer, agentTimer, reportTimer]
  }, [])

  // Stop mock timers
  const stopMockTimers = useCallback(() => {
    mockTimersRef.current.forEach(clearInterval)
    mockTimersRef.current = []
  }, [])

  // Connect to WebSocket server
  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(import.meta.env.VITE_WS_URL ?? 'ws://localhost:8765/ws/dashboard')
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
      stopMockTimers() // Real data flowing, kill mock timers
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        switch (msg.type) {
          case 'alert': {
            const a = msg.data
            const mapped: Alert = {
              id: (a.alert_id || '') + '-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6),
              time: (a.timestamp || '').substring(11, 19) || new Date().toISOString().substring(11, 19),
              ip: a.source_ip || '?.?.?.?',
              country: '--',
              method: 'POST',
              path: a.endpoint || '/unknown',
              type: a.attack_type || 'UNKNOWN',
              score: a.anomaly_score || -0.1,
            }
            setAlerts(prev => [mapped, ...prev].slice(0, 10))
            setStats(prev => ({
              requests: prev.requests + 1,
              threats: prev.threats + 1,
            }))
            break
          }
          case 'honeypots': {
            const grid = (msg.data as any[]).map(h => ({
              status: h.status || 'idle',
              image: h.image || 'web-honeypot',
              ip: h.ip || null,
              port: h.port || null,
            })) as Honeypot[]
            setHoneypots(grid)
            break
          }
          case 'agent_log': {
            const line = msg.data as string
            setAgentLogs(prev => [...prev, line].slice(-25))
            break
          }
          case 'report': {
            setReport(msg.data as string)
            break
          }
        }
      } catch {
        // ignore malformed messages
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
      wsRef.current = null
      startMockTimers() // WS down, fall back to mock data
      // Auto-reconnect after 3 seconds
      reconnectRef.current = setTimeout(connectWs, 3000)
    }

    ws.onerror = () => {
      ws.close() // triggers onclose -> reconnect
    }
  }, [startMockTimers, stopMockTimers])

  useEffect(() => {
    // Clock always runs
    const clock = setInterval(() => setTime(new Date()), 1000)

    // Try WebSocket first; if it fails, onclose starts mock timers
    connectWs()
    // Also start mock timers immediately so there's data while WS connects
    startMockTimers()

    return () => {
      clearInterval(clock)
      stopMockTimers()
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [connectWs, startMockTimers, stopMockTimers])

  return (
    <div className="relative z-10 h-screen max-h-screen flex flex-col gap-3 p-3 font-[var(--font-sans)] overflow-hidden">
      <HeaderBar stats={stats} time={time} wsConnected={wsConnected} />

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-3 min-h-0">
        {/* Left column */}
        <div className="lg:col-span-8 flex flex-col gap-3 min-h-0">
          <ThreatStream alerts={alerts} />
          <DeceptionGrid honeypots={honeypots} />
        </div>

        {/* Right column */}
        <div className="lg:col-span-4 flex flex-col gap-3 min-h-0">
          <AgentConsole logs={agentLogs} />
          <ReportViewer report={report} />
        </div>
      </div>

      <TickerBar />
    </div>
  )
}
