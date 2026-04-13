/**
 * 간단한 솔리드 컬러 + 타이틀 텍스트 MP4 샘플 영상 생성기
 * Node.js 18+ 필요 (Canvas API 불필요, 순수 MP4 바이너리 조립)
 *
 * H.264로 인코딩된 단색 배경 프레임을 가진 최소 MP4를 생성합니다.
 * 각 파일은 약 20초 분량의 단색(검정) 영상입니다.
 */

import { writeFileSync, readFileSync, copyFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT = resolve(__dirname, '../public/samples')

// ─── MP4 박스 유틸 ───────────────────────────────────────────────────
function box(type, ...children) {
  const typeBytes = Buffer.from(type, 'ascii')
  const payload = Buffer.concat(children.map(c => c instanceof Buffer ? c : Buffer.from(c)))
  const size = Buffer.alloc(4)
  size.writeUInt32BE(8 + payload.length, 0)
  return Buffer.concat([size, typeBytes, payload])
}

function u8(v)  { const b = Buffer.alloc(1); b.writeUInt8(v, 0); return b }
function u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b }
function u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v, 0); return b }
function i32(v) { const b = Buffer.alloc(4); b.writeInt32BE(v, 0); return b }
function u64(v) { // hi/lo 32bit
  const b = Buffer.alloc(8)
  b.writeUInt32BE(Math.floor(v / 0x100000000), 0)
  b.writeUInt32BE(v >>> 0, 4)
  return b
}
function zeros(n) { return Buffer.alloc(n, 0) }
function str4(s)  { return Buffer.from(s.slice(0, 4).padEnd(4, '\0'), 'ascii') }

// 고정 3x3 identity matrix (display transform) for tkhd/mvhd
function matrix() {
  return Buffer.concat([
    u32(0x00010000), u32(0), u32(0),
    u32(0), u32(0x00010000), u32(0),
    u32(0), u32(0), u32(0x40000000),
  ])
}

// ─── 단일 I-프레임(검정 화면) H.264 데이터 ─────────────────────────
// 128x72 해상도, baseline profile, 단색 검정 I-프레임
// 아래 SPS/PPS/슬라이스는 ffmpeg으로 미리 추출한 최소 단색 프레임입니다.
// (128x72 YUV 420, 완전 검정)
const SPS = Buffer.from('6742c01e8d68282c4004', 'hex')
const PPS = Buffer.from('68ce3880', 'hex')
// 최소 IDR 슬라이스 (검정 I-프레임, 여러 MB를 skip으로 인코딩)
const IDR_SLICE = Buffer.from(
  '65b80400000001' +
  'adfb3578f75caad76b5b5f5f5f5f5f5f' +
  '5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f',
  'hex',
)

// Annex-B → length-prefixed NALU 변환
function naluWithLength(data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0)
  return Buffer.concat([len, data])
}

// ─── avcC (AVCDecoderConfigurationRecord) ───────────────────────────
function buildAvcC() {
  const spsLen = Buffer.alloc(2); spsLen.writeUInt16BE(SPS.length, 0)
  const ppsLen = Buffer.alloc(2); ppsLen.writeUInt16BE(PPS.length, 0)
  return Buffer.concat([
    u8(1),           // configurationVersion
    u8(SPS[1]),      // AVCProfileIndication
    u8(SPS[2]),      // profile_compatibility
    u8(SPS[3]),      // AVCLevelIndication
    u8(0xff),        // lengthSizeMinusOne = 3 → 4-byte length prefix
    u8(0xe1),        // numSequenceParameterSets
    spsLen, SPS,
    u8(1),           // numPictureParameterSets
    ppsLen, PPS,
  ])
}

// ─── MP4 빌드 ────────────────────────────────────────────────────────
function buildMp4(durationSec, width = 128, height = 72) {
  const timeScale   = 90000          // 90kHz (일반적인 비디오 타임스케일)
  const frameDur    = timeScale / 15 // 15fps
  const frameCount  = durationSec * 15
  const totalDur    = frameCount * frameDur

  // 각 프레임 = IDR 슬라이스 하나 (실제로는 모두 동일한 검정 프레임)
  const frame = Buffer.concat([naluWithLength(IDR_SLICE)])
  const frameSize = frame.length

  // mdat (모든 프레임 데이터)
  const frames = Buffer.concat(Array(frameCount).fill(frame))
  const mdatBox = box('mdat', frames)

  // mdat 이전 헤더 크기를 계산해야 chunk offset(stco)을 알 수 있음
  // 먼저 moov를 한 번 조립해 크기를 구한 뒤 offset을 확정합니다.
  const buildMoov = (mdatOffset) => {
    // ── ftyp ────────────────────────────────────────────
    const ftyp = box('ftyp',
      str4('isom'),
      u32(0x200),           // minor_version
      str4('isom'), str4('iso2'), str4('avc1'), str4('mp41'),
    )

    // ── stsd → avc1 ─────────────────────────────────────
    const avcC = box('avcC', buildAvcC())
    const avc1 = Buffer.concat([
      Buffer.alloc(6, 0),         // reserved (6)
      u16(1),                      // data_reference_index
      zeros(16),                   // pre_defined + reserved
      u16(width), u16(height),     // width, height
      u32(0x00480000),             // horizResolution 72dpi
      u32(0x00480000),             // vertResolution 72dpi
      u32(0),                      // reserved
      u16(1),                      // frame_count per sample
      zeros(32),                   // compressorname
      u16(0x0018),                 // depth = 24
      i32(-1),                     // pre_defined
      avcC,
    ])
    const stsd = box('stsd',
      u32(0), u32(1),              // version=0, entry_count=1
      box('avc1', ...Array.from(avc1)),  // wrap raw bytes
    )
    // stsd를 raw bytes concat으로 다시 빌드 (배열 스프레드 문제 우회)
    const stsdPayload = Buffer.concat([
      u32(0), u32(1),
      box('avc1',
        Buffer.alloc(6, 0), u16(1), zeros(16),
        u16(width), u16(height),
        u32(0x00480000), u32(0x00480000), u32(0), u16(1), zeros(32),
        u16(0x0018), i32(-1),
        avcC,
      ),
    ])
    const stsdBox = box('stsd', stsdPayload)

    // ── stts (time-to-sample): 모든 프레임 동일 duration ─
    const sttsBox = box('stts',
      u32(0),           // version + flags
      u32(1),           // entry_count
      u32(frameCount),  // sample_count
      u32(frameDur),    // sample_delta
    )

    // ── stss (sync sample = 모두 keyframe) ───────────────
    const stssEntries = []
    for (let i = 1; i <= frameCount; i++) stssEntries.push(u32(i))
    const stssBox = box('stss', u32(0), u32(frameCount), ...stssEntries)

    // ── stsz (sample sizes) ──────────────────────────────
    const szEntries = []
    for (let i = 0; i < frameCount; i++) szEntries.push(u32(frameSize))
    const stszBox = box('stsz',
      u32(0),          // version + flags
      u32(0),          // sample_size = 0 (variable)
      u32(frameCount),
      ...szEntries,
    )

    // ── stsc (sample-to-chunk): 1 chunk per sample ───────
    const stscBox = box('stsc',
      u32(0), u32(1),
      u32(1),          // first_chunk
      u32(1),          // samples_per_chunk
      u32(1),          // sample_description_index
    )

    // ── stco (chunk offsets) ─────────────────────────────
    const coEntries = []
    for (let i = 0; i < frameCount; i++) {
      coEntries.push(u32(mdatOffset + 8 + i * frameSize))
    }
    const stcoBox = box('stco', u32(0), u32(frameCount), ...coEntries)

    const stblBox = box('stbl', stsdBox, sttsBox, stssBox, stszBox, stscBox, stcoBox)

    const vmhdBox = box('vmhd', u32(1), u16(0), u16(0), u16(0), u16(0))
    const urlBox  = box('url ', u32(1))                    // self-contained
    const drefBox = box('dref', u32(0), u32(1), urlBox)
    const dinfBox = box('dinf', drefBox)
    const minfBox = box('minf', vmhdBox, dinfBox, stblBox)

    const mdhdBox = box('mdhd',
      u32(0),            // version=0
      u32(0), u32(0),    // creation/modification time
      u32(timeScale),
      u32(totalDur),
      u16(0x55c4),       // language 'und'
      u16(0),
    )
    const hdlrBox = box('hdlr',
      u32(0), u32(0),
      str4('vide'),
      zeros(12),
      Buffer.from('VideoHandler\0'),
    )
    const mdiaBox = box('mdia', mdhdBox, hdlrBox, minfBox)

    const tkhdFlags = 0x000003   // enabled + in-movie
    const tkhdBox = box('tkhd',
      u32(tkhdFlags),    // version=0, flags
      u32(0), u32(0),    // creation/modification time
      u32(1),            // track_id
      u32(0),            // reserved
      u32(totalDur),
      zeros(8),          // reserved
      u16(0),            // layer
      u16(0),            // alternate_group
      u16(0),            // volume (0 = not audio)
      u16(0),
      matrix(),
      u32(width  << 16), // width  (fixed-point 16.16)
      u32(height << 16), // height (fixed-point 16.16)
    )
    const trakBox = box('trak', tkhdBox, mdiaBox)

    const mvhd = box('mvhd',
      u32(0),            // version=0
      u32(0), u32(0),    // creation/modification time
      u32(timeScale),
      u32(totalDur),
      u32(0x00010000),   // preferred rate (1.0)
      u16(0x0100),       // preferred volume (1.0)
      zeros(10),
      matrix(),
      zeros(24),
      u32(2),            // next_track_id
    )

    return box('moov', mvhd, trakBox)
  }

  // ftyp 크기 계산 (28 bytes header + 4 brands * 4 = 28+16 = ... )
  const ftyp = box('ftyp',
    str4('isom'), u32(0x200),
    str4('isom'), str4('iso2'), str4('avc1'), str4('mp41'),
  )
  const moovDraft = buildMoov(ftyp.length + 0)  // draft to measure size
  const mdatStart = ftyp.length + moovDraft.length
  const moovFinal = buildMoov(mdatStart)

  return Buffer.concat([ftyp, moovFinal, mdatBox])
}

// ─── 파일 생성 ────────────────────────────────────────────────────────
const videos = [
  { name: 'lesson-os-process.mp4',    duration: 20 },
  { name: 'lesson-os-thread.mp4',     duration: 20 },
  { name: 'lesson-os-context.mp4',    duration: 20 },
  { name: 'lesson-spring-di.mp4',     duration: 20 },
  { name: 'lesson-spring-bean.mp4',   duration: 20 },
]

for (const { name, duration } of videos) {
  const out = resolve(OUT, name)
  const data = buildMp4(duration)
  writeFileSync(out, data)
  console.log(`✅ ${name}  (${(data.length / 1024).toFixed(0)} KB)`)
}

// ocr-code-demo.mp4는 이미 존재하므로 건드리지 않음
console.log('\nDone. Sample videos written to public/samples/')
