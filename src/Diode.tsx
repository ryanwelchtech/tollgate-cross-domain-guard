import { useEffect, useRef } from 'react';
import type { ReassemblyStats } from '../core/diode.ts';

export interface DiodeRun {
  frames: number;
  fates: boolean[]; // true = delivered
  delivered: number; // frames transmitted so far
  phase: 'sending' | 'done';
  stats: ReassemblyStats;
  bytes: number;
  verdict?: 'accepted' | 'quarantined' | 'unrecoverable';
  problems?: string[];
}

/** Canvas view of frames crossing the diode: low side left, high side right, nothing flows back. */
export function DiodeView({ run }: { run: DiodeRun | null }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    let raf = 0;
    const c = ref.current!;
    const ctx = c.getContext('2d')!;
    const draw = (t: number) => {
      const W = (c.width = c.clientWidth * devicePixelRatio);
      const H = (c.height = c.clientHeight * devicePixelRatio);
      ctx.scale(devicePixelRatio, devicePixelRatio);
      const w = W / devicePixelRatio, h = H / devicePixelRatio;
      ctx.clearRect(0, 0, w, h);
      const mid = w / 2;
      // sides
      ctx.fillStyle = 'rgba(56,189,248,0.06)'; ctx.fillRect(0, 0, mid - 18, h);
      ctx.fillStyle = 'rgba(244,114,182,0.06)'; ctx.fillRect(mid + 18, 0, w - mid - 18, h);
      ctx.font = '600 10px ui-monospace, monospace';
      ctx.fillStyle = '#38bdf8'; ctx.fillText('LOW', 8, 14);
      ctx.fillStyle = '#f472b6'; ctx.fillText('HIGH', w - 36, 14);
      // diode symbol
      ctx.strokeStyle = '#64748b'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(mid - 10, h / 2 - 12); ctx.lineTo(mid + 8, h / 2); ctx.lineTo(mid - 10, h / 2 + 12); ctx.closePath(); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(mid + 10, h / 2 - 12); ctx.lineTo(mid + 10, h / 2 + 12); ctx.stroke();
      ctx.setLineDash([3, 4]); ctx.beginPath(); ctx.moveTo(mid, 0); ctx.lineTo(mid, h / 2 - 16); ctx.moveTo(mid, h / 2 + 16); ctx.lineTo(mid, h); ctx.stroke(); ctx.setLineDash([]);
      const r = runRef.current;
      if (r) {
        const lanes = 7;
        const window_ = 26;
        const start = Math.max(0, r.delivered - window_);
        for (let i = start; i < r.delivered; i++) {
          const age = (r.delivered - i) / window_;
          const lane = i % lanes;
          const y = 26 + lane * ((h - 40) / (lanes - 1));
          const ok = r.fates[i];
          const x = 20 + age * 0 + (1 - age) * 0 + ((1 - age) * (w - 40));
          const xx = ok ? x : Math.min(x, mid - 22);
          ctx.globalAlpha = Math.max(0.15, 1 - age * 0.8);
          if (ok) {
            ctx.fillStyle = r.phase === 'done' ? '#22c55e' : '#e2e8f0';
            ctx.fillRect(xx - 5, y - 3, 10, 6);
          } else {
            ctx.strokeStyle = '#ef4444'; ctx.lineWidth = 2;
            ctx.beginPath(); ctx.moveTo(xx - 4, y - 4); ctx.lineTo(xx + 4, y + 4); ctx.moveTo(xx + 4, y - 4); ctx.lineTo(xx - 4, y + 4); ctx.stroke();
          }
          ctx.globalAlpha = 1;
        }
        void t;
      } else {
        ctx.fillStyle = '#475569'; ctx.font = '11px ui-sans-serif, system-ui';
        ctx.fillText('awaiting release', mid - 44, h - 10);
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  const s = run?.stats;
  const dropped = run ? run.fates.slice(0, run.delivered).filter((x) => !x).length : 0;
  return (
    <div className="diode">
      <canvas ref={ref} />
      <div className="dstats">
        <span>frames <b>{run ? `${run.delivered}/${run.frames}` : '-'}</b></span>
        <span>dropped <b className="bad">{run ? dropped : '-'}</b></span>
        <span>dupes <b>{s ? s.duplicates : '-'}</b></span>
        <span>FEC rebuilt <b className="good">{s ? s.recovered : '-'}</b></span>
        <span>ACKs <b>0</b></span>
      </div>
    </div>
  );
}
