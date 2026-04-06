import type { OcrSelectionRect, VideoOcrResult } from '../lib/video-ocr'

type LearningOcrPanelProps = {
  busy: boolean
  selecting: boolean
  statusTone: 'idle' | 'loading' | 'success' | 'error'
  statusMessage: string
  progressPercent: number
  result: VideoOcrResult | null
  onRunCurrentFrame: () => void
  onStartRegionSelection: () => void
  onCancelSelection: () => void
  onCopy: () => void
}

function formatSelection(selection: OcrSelectionRect | null) {
  if (!selection) return '전체 프레임'
  return `${Math.round(selection.x)}, ${Math.round(selection.y)} · ${Math.round(selection.width)}x${Math.round(selection.height)}`
}

export default function LearningOcrPanel({
  busy,
  selecting,
  statusTone,
  statusMessage,
  progressPercent,
  result,
  onRunCurrentFrame,
  onStartRegionSelection,
  onCancelSelection,
  onCopy,
}: LearningOcrPanelProps) {
  const statusClassName = statusTone === 'error'
    ? 'border-red-100 bg-red-50 text-red-700'
    : statusTone === 'success'
      ? 'border-emerald-100 bg-emerald-50 text-emerald-700'
      : statusTone === 'loading'
        ? 'border-amber-100 bg-amber-50 text-amber-700'
        : 'border-gray-200 bg-gray-50 text-gray-600'

  return (
    <div className="space-y-6">
      <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Video OCR</div>
            <h2 className="mt-2 text-xl font-black text-gray-900">현재 프레임 텍스트 추출</h2>
            <p className="mt-2 text-sm leading-6 text-gray-600">
              학습 영상의 현재 프레임에서 코드나 텍스트를 추출합니다. 첫 실행은 OCR 엔진 로딩 때문에 조금 걸릴 수 있습니다.
            </p>
          </div>
          <div className="rounded-2xl bg-gray-900 px-3 py-2 text-right text-white">
            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-white/60">Engine</div>
            <div className="mt-1 text-sm font-black">{busy ? 'Working' : 'Ready'}</div>
          </div>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <button
            type="button"
            onClick={onRunCurrentFrame}
            disabled={busy}
            className="rounded-2xl bg-[#00c471] px-4 py-3 text-sm font-bold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? 'OCR 실행 중...' : '현재 프레임 OCR'}
          </button>
          <button
            type="button"
            onClick={selecting ? onCancelSelection : onStartRegionSelection}
            disabled={busy}
            className={`rounded-2xl border px-4 py-3 text-sm font-bold transition ${
              selecting
                ? 'border-red-200 bg-red-50 text-red-600 hover:bg-red-100'
                : 'border-gray-200 bg-white text-gray-700 hover:bg-gray-50'
            } disabled:cursor-not-allowed disabled:opacity-60`}
          >
            {selecting ? '영역 선택 취소' : '영역 선택 OCR'}
          </button>
        </div>

        <div className={`mt-4 rounded-2xl border px-4 py-3 text-sm ${statusClassName}`}>
          <div className="font-semibold">{statusMessage}</div>
          {busy ? (
            <div className="mt-3">
              <div className="h-2 overflow-hidden rounded-full bg-white/70">
                <div className="h-full rounded-full bg-current transition-all" style={{ width: `${Math.max(progressPercent, 8)}%` }} />
              </div>
              <div className="mt-2 text-xs opacity-80">{progressPercent}%</div>
            </div>
          ) : null}
        </div>

        {selecting ? (
          <div className="mt-4 rounded-2xl border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-700">
            영상 위에서 필요한 부분만 드래그해서 선택하면 해당 영역만 OCR합니다.
          </div>
        ) : null}
      </section>

      <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex items-center justify-between gap-4">
          <div>
            <h3 className="text-lg font-black text-gray-900">OCR 결과</h3>
            <p className="mt-1 text-xs text-gray-400">
              {result
                ? `신뢰도 ${result.confidence.toFixed(1)}% · ${result.mode === 'region' ? '영역 OCR' : '전체 프레임 OCR'}`
                : '아직 추출된 OCR 결과가 없습니다.'}
            </p>
          </div>
          <button
            type="button"
            onClick={onCopy}
            disabled={!result?.text}
            className="rounded-xl border border-gray-200 px-3 py-2 text-xs font-bold text-gray-600 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-40"
          >
            복사
          </button>
        </div>

        {result ? (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3">
                <div className="text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Timestamp</div>
                <div className="mt-1 text-sm font-bold text-gray-900">{result.timestampSecond}s</div>
              </div>
              <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3">
                <div className="text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Mode</div>
                <div className="mt-1 text-sm font-bold text-gray-900">{result.mode === 'region' ? 'Region' : 'Full Frame'}</div>
              </div>
              <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3">
                <div className="text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Area</div>
                <div className="mt-1 text-sm font-bold text-gray-900">{formatSelection(result.selection)}</div>
              </div>
            </div>

            <div>
              <div className="mb-2 text-xs font-black uppercase tracking-[0.16em] text-gray-400">Recognized Text</div>
              <pre className="overflow-x-auto rounded-2xl border border-gray-200 bg-[#111827] p-4 text-sm leading-6 whitespace-pre-wrap text-gray-100">
                {result.text || '(텍스트가 감지되지 않았습니다.)'}
              </pre>
            </div>

            <div>
              <div className="mb-2 text-xs font-black uppercase tracking-[0.16em] text-gray-400">Code Blocks</div>
              {result.codeBlocks.length ? (
                <div className="space-y-3">
                  {result.codeBlocks.map((block, index) => (
                    <pre key={`${result.id}-${index}`} className="overflow-x-auto rounded-2xl border border-emerald-100 bg-emerald-50 p-4 text-sm leading-6 whitespace-pre-wrap text-gray-800">
                      {block}
                    </pre>
                  ))}
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 px-4 py-6 text-sm text-gray-500">
                  명확한 코드 블록은 감지되지 않았습니다.
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 px-4 py-8 text-sm text-gray-500">
            OCR을 실행하면 추출된 텍스트와 코드 블록이 여기 표시됩니다.
          </div>
        )}
      </section>
    </div>
  )
}
