/**
 * MP4 Faststart 변환 스크립트
 * moov atom을 파일 앞으로 이동시켜 브라우저가 다운로드 시작 즉시 재생할 수 있게 합니다.
 *
 * 사용법: node frontend/scripts/mp4-faststart.mjs <input.mp4> [output.mp4]
 * output을 생략하면 원본 파일을 덮어씁니다.
 */

import { readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { resolve } from 'node:path'

// ── Box 파서 ────────────────────────────────────────────────────────────

function readU32(buf, offset) {
  return buf.readUInt32BE(offset)
}
function writeU32(buf, value, offset) {
  buf.writeUInt32BE(value >>> 0, offset)
}

/**
 * 파일의 최상위 box 목록을 파싱합니다.
 * 반환: [{ type, start, size, headerSize }]
 */
function parseTopBoxes(buf) {
  const boxes = []
  let offset = 0

  while (offset + 8 <= buf.length) {
    const rawSize = readU32(buf, offset)
    const type = buf.toString('ascii', offset + 4, offset + 8)

    let size, headerSize

    if (rawSize === 1) {
      // 64-bit extended size
      const hi = readU32(buf, offset + 8)
      const lo = readU32(buf, offset + 12)
      size = hi * 0x1_0000_0000 + lo
      headerSize = 16
    } else if (rawSize === 0) {
      // extends to EOF
      size = buf.length - offset
      headerSize = 8
    } else {
      size = rawSize
      headerSize = 8
    }

    if (size < 8) break

    boxes.push({ type, start: offset, size, headerSize })
    offset += size
  }

  return boxes
}

/**
 * moov 내부를 재귀적으로 순회하며 stco/co64 오프셋을 delta만큼 조정합니다.
 * buf는 전체 파일 버퍼이고 offset/end는 현재 컨테이너의 payload 범위입니다.
 */
function adjustOffsets(buf, offset, end, delta) {
  let pos = offset
  while (pos + 8 <= end) {
    const rawSize = readU32(buf, pos)
    if (rawSize < 8) break
    const type = buf.toString('ascii', pos + 4, pos + 8)
    const size = rawSize === 1
      ? readU32(buf, pos + 8) * 0x1_0000_0000 + readU32(buf, pos + 12)
      : rawSize

    if (type === 'stco') {
      // FullBox: version(1)+flags(3) = 4 bytes, then entry_count(4), then offsets
      const count = readU32(buf, pos + 12)
      for (let i = 0; i < count; i++) {
        const off = pos + 16 + i * 4
        writeU32(buf, readU32(buf, off) + delta, off)
      }
    } else if (type === 'co64') {
      const count = readU32(buf, pos + 12)
      for (let i = 0; i < count; i++) {
        const off = pos + 16 + i * 8
        const hi = readU32(buf, off)
        const lo = readU32(buf, off + 4)
        const newVal = hi * 0x1_0000_0000 + lo + delta
        writeU32(buf, Math.floor(newVal / 0x1_0000_0000), off)
        writeU32(buf, newVal, off + 4)
      }
    } else if (['moov', 'trak', 'mdia', 'minf', 'stbl', 'udta', 'meta'].includes(type)) {
      const payloadStart = pos + (size > 0xffffffff ? 16 : 8)
      adjustOffsets(buf, payloadStart, pos + size, delta)
    }

    pos += size
  }
}

// ── 메인 ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2)
if (!args.length) {
  console.error('사용법: node mp4-faststart.mjs <input.mp4> [output.mp4]')
  process.exit(1)
}

const inputPath  = resolve(args[0])
const outputPath = args[1] ? resolve(args[1]) : inputPath
const inPlace    = inputPath === outputPath

console.log(`입력: ${inputPath}`)

const buf = readFileSync(inputPath)
const boxes = parseTopBoxes(buf)

const ftypBox  = boxes.find(b => b.type === 'ftyp')
const moovBox  = boxes.find(b => b.type === 'moov')
const mdatBox  = boxes.find(b => b.type === 'mdat')

if (!moovBox) {
  console.error('moov box를 찾을 수 없습니다. 유효한 MP4 파일인지 확인하세요.')
  process.exit(1)
}

if (!mdatBox) {
  console.error('mdat box를 찾을 수 없습니다.')
  process.exit(1)
}

// moov가 이미 mdat 앞에 있으면 변환 불필요
if (moovBox.start < mdatBox.start) {
  console.log('✅ 이미 faststart 형식입니다. 변환이 필요 없습니다.')
  process.exit(0)
}

console.log(`moov 위치: ${moovBox.start} (파일 끝 쪽) → 앞으로 이동 중...`)

// 새로운 레이아웃: [ftyp?] [moov] [기타 non-mdat/moov/ftyp boxes] [mdat]
const ftypData = ftypBox ? buf.slice(ftypBox.start, ftypBox.start + ftypBox.size) : Buffer.alloc(0)
const moovData = Buffer.from(buf.slice(moovBox.start, moovBox.start + moovBox.size)) // copy — 수정 예정
const mdatData = buf.slice(mdatBox.start, mdatBox.start + mdatBox.size)

// ftyp + moov 다음에 mdat이 시작하는 새 오프셋 계산
const newMdatOffset = ftypData.length + moovData.length
const oldMdatOffset = mdatBox.start

// stco/co64 오프셋을 (newMdatOffset - oldMdatOffset)만큼 조정
const delta = newMdatOffset - oldMdatOffset
adjustOffsets(moovData, 8, moovData.length, delta)

// 새 파일 조립
const output = Buffer.concat([ftypData, moovData, mdatData])

if (inPlace) {
  const tmpPath = inputPath + '.tmp'
  writeFileSync(tmpPath, output)
  unlinkSync(inputPath)
  renameSync(tmpPath, inputPath)
} else {
  writeFileSync(outputPath, output)
}

const saved = buf.length - output.length  // 보통 0 (크기 동일)
console.log(`✅ 완료: ${outputPath}`)
console.log(`   원본 크기: ${(buf.length / 1024 / 1024).toFixed(2)} MB`)
console.log(`   변환 크기: ${(output.length / 1024 / 1024).toFixed(2)} MB`)
console.log(`   moov 이동: +${delta} bytes (오프셋 조정 적용)`)