// ==========================================
// Video.js 플레이어 초기화
// ==========================================
const player = videojs('video-player', {
  controls: true,
  autoplay: false,
  preload: 'auto',
  fluid: true,
  playbackRates: [0.5, 1, 1.5, 2]
});

// ==========================================
// 모드 관리
// ==========================================
let currentMode = 'full'; // 'full' or 'select'
let isSelecting = false;
let selectionStart = null;
let selectionEnd = null;

const overlay = document.getElementById('selection-overlay');
const selectionBox = document.getElementById('selection-box');
const modeFullBtn = document.getElementById('mode-full');
const modeSelectBtn = document.getElementById('mode-select');
const modeInfo = document.getElementById('mode-info');

// 모드 전환
modeFullBtn.addEventListener('click', () => {
  currentMode = 'full';
  modeFullBtn.classList.add('active');
  modeSelectBtn.classList.remove('active');
  overlay.classList.remove('active');
  modeInfo.textContent = '📷 버튼을 눌러 현재 화면 전체를 OCR합니다';
  resetSelection();
});

modeSelectBtn.addEventListener('click', () => {
  currentMode = 'select';
  modeSelectBtn.classList.add('active');
  modeFullBtn.classList.remove('active');
  overlay.classList.add('active');
  modeInfo.textContent = '🖱️ 비디오 위에 드래그하여 OCR 영역을 선택하세요';
  resetSelection();
});

// ==========================================
// 드래그 선택 이벤트
// ==========================================
overlay.addEventListener('mousedown', (e) => {
  if (currentMode !== 'select') return;

  isSelecting = true;
  const rect = overlay.getBoundingClientRect();
  selectionStart = {
    x: e.clientX - rect.left,
    y: e.clientY - rect.top
  };
  selectionEnd = { ...selectionStart };
  updateSelectionBox();
});

overlay.addEventListener('mousemove', (e) => {
  if (!isSelecting || currentMode !== 'select') return;

  const rect = overlay.getBoundingClientRect();
  selectionEnd = {
    x: e.clientX - rect.left,
    y: e.clientY - rect.top
  };
  updateSelectionBox();
});

overlay.addEventListener('mouseup', (e) => {
  if (!isSelecting || currentMode !== 'select') return;

  isSelecting = false;

  // 최소 크기 체크 (너무 작은 드래그는 무시)
  const width = Math.abs(selectionEnd.x - selectionStart.x);
  const height = Math.abs(selectionEnd.y - selectionStart.y);

  if (width > 20 && height > 20) {
    // 선택 영역 OCR 실행
    performRegionOCR();
  } else {
    resetSelection();
  }
});

// 드래그 중 마우스가 영역 밖으로 나가면 취소
overlay.addEventListener('mouseleave', () => {
  if (isSelecting) {
    isSelecting = false;
    resetSelection();
  }
});

function updateSelectionBox() {
  if (!selectionStart || !selectionEnd) return;

  const x = Math.min(selectionStart.x, selectionEnd.x);
  const y = Math.min(selectionStart.y, selectionEnd.y);
  const width = Math.abs(selectionEnd.x - selectionStart.x);
  const height = Math.abs(selectionEnd.y - selectionStart.y);

  selectionBox.style.left = `${x}px`;
  selectionBox.style.top = `${y}px`;
  selectionBox.style.width = `${width}px`;
  selectionBox.style.height = `${height}px`;
  selectionBox.style.display = 'block';
}

function resetSelection() {
  selectionBox.style.display = 'none';
  selectionStart = null;
  selectionEnd = null;
  isSelecting = false;
}

// ==========================================
// OCR 커스텀 버튼 컴포넌트
// ==========================================
const Button = videojs.getComponent('Button');

class OcrButton extends Button {
  constructor(player, options) {
    super(player, options);
    this.controlText('OCR 캡처');
    this.addClass('vjs-ocr-button');
  }

  buildCSSClass() {
    return `vjs-control vjs-button ${super.buildCSSClass()}`;
  }

  handleClick() {
    // 전체 화면 모드에서만 버튼 클릭으로 OCR 실행
    if (currentMode === 'full') {
      const videoElement = player.el().querySelector('video');
      performOCR(videoElement);
    } else {
      // 영역 선택 모드에서는 안내 메시지
      updateStatus('🖱️ 비디오 위에 드래그하여 영역을 선택하세요', 'processing');
    }
  }
}

// Video.js에 OCR 버튼 등록
videojs.registerComponent('OcrButton', OcrButton);
player.getChild('controlBar').addChild('OcrButton', {}, 0); // 컨트롤바 맨 앞에 추가

// ==========================================
// UI 업데이트 헬퍼 함수
// ==========================================
function updateStatus(message, type = 'processing') {
  const statusEl = document.getElementById('status');
  statusEl.textContent = message;
  statusEl.className = `ocr-status ${type}`;
}

function showResults() {
  document.getElementById('preview-container').style.display = 'grid';
  document.getElementById('results').style.display = 'block';
}

// ==========================================
// 이미지 전처리 함수들
// ==========================================

/**
 * 1. 비디오 프레임 캡처 (전체 또는 영역)
 */
function captureFrame(videoElement, region = null) {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');

  if (region) {
    // 영역 선택 모드: 선택된 부분만 캡처
    const videoRect = videoElement.getBoundingClientRect();
    const scaleX = videoElement.videoWidth / videoRect.width;
    const scaleY = videoElement.videoHeight / videoRect.height;

    const sourceX = region.x * scaleX;
    const sourceY = region.y * scaleY;
    const sourceWidth = region.width * scaleX;
    const sourceHeight = region.height * scaleY;

    canvas.width = sourceWidth;
    canvas.height = sourceHeight;

    ctx.drawImage(
        videoElement,
        sourceX, sourceY, sourceWidth, sourceHeight,
        0, 0, sourceWidth, sourceHeight
    );
  } else {
    // 전체 화면 모드
    canvas.width = videoElement.videoWidth;
    canvas.height = videoElement.videoHeight;
    ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);
  }

  return {
    canvas: canvas,
    imageData: ctx.getImageData(0, 0, canvas.width, canvas.height)
  };
}

/**
 * 2. 그레이스케일 변환
 */
function convertToGrayscale(imageData) {
  const data = imageData.data;

  for (let i = 0; i < data.length; i += 4) {
    // 가중 평균 (인간 눈의 색 민감도 반영)
    const gray = data[i] * 0.299 + data[i + 1] * 0.587 + data[i + 2] * 0.114;
    data[i] = data[i + 1] = data[i + 2] = gray;
  }

  return imageData;
}

/**
 * 3. Otsu's Method를 이용한 자동 임계값 계산
 */
function calculateOtsuThreshold(imageData) {
  const data = imageData.data;
  const histogram = new Array(256).fill(0);
  const total = imageData.width * imageData.height;

  // 히스토그램 생성
  for (let i = 0; i < data.length; i += 4) {
    histogram[data[i]]++;
  }

  let sum = 0;
  for (let i = 0; i < 256; i++) {
    sum += i * histogram[i];
  }

  let sumB = 0;
  let wB = 0;
  let wF = 0;
  let maxVariance = 0;
  let threshold = 0;

  for (let i = 0; i < 256; i++) {
    wB += histogram[i];
    if (wB === 0) continue;

    wF = total - wB;
    if (wF === 0) break;

    sumB += i * histogram[i];

    const mB = sumB / wB;
    const mF = (sum - sumB) / wF;

    const variance = wB * wF * (mB - mF) * (mB - mF);

    if (variance > maxVariance) {
      maxVariance = variance;
      threshold = i;
    }
  }

  return threshold;
}

/**
 * 4. 이진화 (Binarization)
 */
function binarize(imageData, threshold) {
  const data = imageData.data;

  for (let i = 0; i < data.length; i += 4) {
    const value = data[i] > threshold ? 255 : 0;
    data[i] = data[i + 1] = data[i + 2] = value;
  }

  return imageData;
}

/**
 * 5. 대비 강화
 */
function enhanceContrast(imageData, factor = 1.5) {
  const data = imageData.data;

  for (let i = 0; i < data.length; i += 4) {
    data[i] = Math.min(255, Math.max(0, (data[i] - 128) * factor + 128));
    data[i + 1] = Math.min(255, Math.max(0, (data[i + 1] - 128) * factor + 128));
    data[i + 2] = Math.min(255, Math.max(0, (data[i + 2] - 128) * factor + 128));
  }

  return imageData;
}

/**
 * 6. 노이즈 제거 (Median Filter 3x3)
 */
function removeNoise(imageData) {
  const data = imageData.data;
  const width = imageData.width;
  const height = imageData.height;
  const temp = new Uint8ClampedArray(data);

  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      const neighbors = [];

      // 3x3 커널
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const idx = ((y + dy) * width + (x + dx)) * 4;
          neighbors.push(temp[idx]);
        }
      }

      // 중앙값 선택
      neighbors.sort((a, b) => a - b);
      const median = neighbors[4];

      const idx = (y * width + x) * 4;
      data[idx] = data[idx + 1] = data[idx + 2] = median;
    }
  }

  return imageData;
}

/**
 * 7-1. 샤프닝 필터 (선명도 향상)
 */
function sharpenImage(imageData) {
  const data = imageData.data;
  const width = imageData.width;
  const height = imageData.height;
  const temp = new Uint8ClampedArray(data);

  // 샤프닝 커널 (중심 강화)
  const kernel = [
    0, -1, 0,
    -1, 5, -1,
    0, -1, 0
  ];

  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      let sum = 0;

      for (let ky = -1; ky <= 1; ky++) {
        for (let kx = -1; kx <= 1; kx++) {
          const idx = ((y + ky) * width + (x + kx)) * 4;
          const kernelIdx = (ky + 1) * 3 + (kx + 1);
          sum += temp[idx] * kernel[kernelIdx];
        }
      }

      const idx = (y * width + x) * 4;
      const value = Math.min(255, Math.max(0, sum));
      data[idx] = data[idx + 1] = data[idx + 2] = value;
    }
  }

  return imageData;
}

/**
 * 7-2. Adaptive Thresholding (지역 적응형 이진화)
 */
function adaptiveBinarize(imageData, blockSize = 15) {
  const data = imageData.data;
  const width = imageData.width;
  const height = imageData.height;
  const temp = new Uint8ClampedArray(data);
  const halfBlock = Math.floor(blockSize / 2);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let sum = 0;
      let count = 0;

      // 지역 평균 계산
      for (let dy = -halfBlock; dy <= halfBlock; dy++) {
        for (let dx = -halfBlock; dx <= halfBlock; dx++) {
          const ny = Math.min(height - 1, Math.max(0, y + dy));
          const nx = Math.min(width - 1, Math.max(0, x + dx));
          const idx = (ny * width + nx) * 4;
          sum += temp[idx];
          count++;
        }
      }

      const localThreshold = (sum / count) * 0.95; // 약간 어둡게
      const idx = (y * width + x) * 4;
      const value = temp[idx] > localThreshold ? 255 : 0;
      data[idx] = data[idx + 1] = data[idx + 2] = value;
    }
  }

  return imageData;
}

/**
 * 7-3. 이미지 크기 확대 (OCR 정확도 향상)
 */
function upscaleImage(canvas, scale = 2) {
  const newCanvas = document.createElement('canvas');
  const ctx = newCanvas.getContext('2d');

  newCanvas.width = canvas.width * scale;
  newCanvas.height = canvas.height * scale;

  // 픽셀 보간 없이 확대 (선명도 유지)
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(canvas, 0, 0, newCanvas.width, newCanvas.height);

  return newCanvas;
}

/**
 * 7. 전처리 파이프라인 실행 및 미리보기 생성 (개선됨)
 */
function preprocessImage(videoElement, region = null) {
  updateStatus('📸 프레임 캡처 중...', 'processing');

  // 원본 캡처 (전체 또는 영역)
  const { canvas: originalCanvas, imageData } = captureFrame(videoElement, region);

  // 2배 확대 (해상도 향상)
  const upscaledCanvas = upscaleImage(originalCanvas, 2);
  const upscaledCtx = upscaledCanvas.getContext('2d');
  let processed = upscaledCtx.getImageData(0, 0, upscaledCanvas.width, upscaledCanvas.height);

  // 각 단계별 캔버스 생성
  const stages = {
    original: originalCanvas,
    grayscale: document.createElement('canvas'),
    binary: document.createElement('canvas'),
    denoised: document.createElement('canvas')
  };

  // 캔버스 크기 설정 (미리보기는 원본 크기로)
  Object.values(stages).forEach(canvas => {
    canvas.width = originalCanvas.width;
    canvas.height = originalCanvas.height;
  });

  // 1단계: 그레이스케일
  updateStatus('🎨 그레이스케일 변환 중...', 'processing');
  processed = convertToGrayscale(processed);

  // 미리보기 저장 (축소)
  const tempCanvas = document.createElement('canvas');
  tempCanvas.width = upscaledCanvas.width;
  tempCanvas.height = upscaledCanvas.height;
  tempCanvas.getContext('2d').putImageData(processed, 0, 0);
  stages.grayscale.getContext('2d').drawImage(tempCanvas, 0, 0, originalCanvas.width, originalCanvas.height);

  // 2단계: 대비 강화
  updateStatus('✨ 대비 강화 중...', 'processing');
  processed = enhanceContrast(processed, 2.0); // 대비 계수 증가

  // 3단계: 샤프닝
  updateStatus('🔍 선명도 향상 중...', 'processing');
  processed = sharpenImage(processed);

  // 4단계: Adaptive 이진화 (Otsu 대신)
  updateStatus('⚫⚪ 적응형 이진화 처리 중...', 'processing');
  processed = adaptiveBinarize(new ImageData(
      new Uint8ClampedArray(processed.data),
      processed.width,
      processed.height
  ), 21); // 블록 크기

  // 미리보기 저장
  tempCanvas.getContext('2d').putImageData(processed, 0, 0);
  stages.binary.getContext('2d').drawImage(tempCanvas, 0, 0, originalCanvas.width, originalCanvas.height);

  // 5단계: 노이즈 제거
  updateStatus('🧹 노이즈 제거 중...', 'processing');
  processed = removeNoise(new ImageData(
      new Uint8ClampedArray(processed.data),
      processed.width,
      processed.height
  ));

  // 최종 미리보기 저장
  tempCanvas.getContext('2d').putImageData(processed, 0, 0);
  stages.denoised.getContext('2d').drawImage(tempCanvas, 0, 0, originalCanvas.width, originalCanvas.height);

  // 미리보기 표시
  displayPreviews(stages);

  // 최종 이미지 반환 (확대된 상태로)
  const finalCanvas = document.createElement('canvas');
  finalCanvas.width = processed.width;
  finalCanvas.height = processed.height;
  finalCanvas.getContext('2d').putImageData(processed, 0, 0);

  return finalCanvas.toDataURL();
}

/**
 * 8. 전처리 이미지 미리보기 표시
 */
function displayPreviews(stages) {
  const canvasIds = {
    original: 'original-canvas',
    grayscale: 'grayscale-canvas',
    binary: 'binary-canvas',
    denoised: 'denoised-canvas'
  };

  Object.entries(canvasIds).forEach(([stage, id]) => {
    const targetCanvas = document.getElementById(id);
    const ctx = targetCanvas.getContext('2d');

    targetCanvas.width = stages[stage].width;
    targetCanvas.height = stages[stage].height;

    ctx.drawImage(stages[stage], 0, 0);
  });
}

// ==========================================
// OCR 실행 및 결과 처리
// ==========================================

/**
 * 코드 텍스트 정제 (라인 넘버, 불필요한 문자 제거)
 */
function cleanCodeText(text) {
  let cleaned = text;

  // 1. 각 줄별로 처리
  const lines = cleaned.split('\n');
  const processedLines = lines.map(line => {
    // 라인 넘버 패턴 제거
    // 패턴: "1 ", "12 ", "123 ", "1:", "12:", "123:", "1|", "12|" 등
    return line
        .replace(/^\s*\d{1,4}[\s:|]+/, '')  // 앞쪽 라인 넘버
        .replace(/^\s*\d{1,4}\s*$/, '')     // 라인 넘버만 있는 줄
        .trim();
  });

  // 2. 빈 줄 제거하되 코드 블록 내부는 유지
  cleaned = processedLines
      .filter(line => line.length > 0)
      .join('\n');

  // 3. OCR 오인식 문자 교정
  cleaned = cleaned
      .replace(/[`'']/g, "'")           // 백틱, 다양한 따옴표 통일
      .replace(/[""]/g, '"')            // 큰따옴표 통일
      .replace(/\s{2,}/g, ' ');         // 연속 공백 제거

  return cleaned;
}

/**
 * 코드 블록 추출 정규식 (개선됨)
 */
function extractCodeBlocks(text) {
  // 먼저 텍스트 정제
  const cleanedText = cleanCodeText(text);

  const patterns = [
    // JavaScript/TypeScript 함수
    /(?:function|const|let|var|class)\s+\w+[\s\S]*?[{][\s\S]*?[}]/g,
    // Python 함수/클래스
    /(?:def|class)\s+\w+[\s\S]*?:/g,
    // 화살표 함수
    /(?:const|let|var)?\s*\w+\s*=\s*\([^)]*\)\s*=>\s*[{][\s\S]*?[}]/g,
    // import/export 문
    /(?:import|export)[\s\S]*?;/g,
    // 일반 중괄호 블록 (if, for, while 등)
    /(?:if|for|while|switch)\s*\([^)]*\)\s*[{][\s\S]*?[}]/g,
    // HTML 태그
    /<[a-zA-Z][\s\S]*?>/g,
    // CSS 규칙
    /[.#]?[\w-]+\s*[{][\s\S]*?[}]/g
  ];

  const codeBlocks = [];
  const seen = new Set();

  patterns.forEach(pattern => {
    const matches = cleanedText.match(pattern) || [];
    matches.forEach(match => {
      const trimmed = match.trim();
      // 길이 제한 및 중복 제거
      if (trimmed.length > 5 && trimmed.length < 2000 && !seen.has(trimmed)) {
        // 라인 넘버가 남아있는지 재확인
        const finalCleaned = cleanCodeText(trimmed);
        if (finalCleaned.length > 5) {
          codeBlocks.push(finalCleaned);
          seen.add(trimmed);
        }
      }
    });
  });

  return codeBlocks;
}

/**
 * 라인별 분석 (디버깅용)
 */
function analyzeLineNumbers(text) {
  const lines = text.split('\n');
  const withLineNumbers = [];
  const withoutLineNumbers = [];

  lines.forEach(line => {
    if (/^\s*\d{1,4}[\s:|]+/.test(line)) {
      withLineNumbers.push(line);
    } else if (line.trim().length > 0) {
      withoutLineNumbers.push(line);
    }
  });

  return {
    totalLines: lines.length,
    linesWithNumbers: withLineNumbers.length,
    linesWithoutNumbers: withoutLineNumbers.length,
    samples: {
      withNumbers: withLineNumbers.slice(0, 3),
      withoutNumbers: withoutLineNumbers.slice(0, 3)
    }
  };
}

/**
 * OCR 메인 함수
 */
async function performOCR(videoElement, region = null) {
  try {
    showResults();

    // 1. 이미지 전처리
    const preprocessedImage = preprocessImage(videoElement, region);

    // 2. Tesseract.js OCR 실행
    updateStatus('🔍 텍스트 인식 중... (3~5초 소요)', 'processing');

    const result = await Tesseract.recognize(
        preprocessedImage,
        'kor+eng', // 한국어 + 영어
        {
          logger: m => {
            if (m.status === 'recognizing text') {
              updateStatus(`🔍 텍스트 인식 중... ${Math.round(m.progress * 100)}%`, 'processing');
            }
          },
          tessedit_pageseg_mode: Tesseract.PSM.AUTO, // 페이지 분할 모드
          tessedit_ocr_engine_mode: Tesseract.OEM.LSTM_ONLY, // LSTM 엔진 사용
        }
    );

    // 3. 결과 표시
    const rawText = result.data.text;
    const confidence = result.data.confidence;
    const codeBlocks = extractCodeBlocks(rawText);

    displayResults(rawText, confidence, codeBlocks);

    updateStatus(`✅ OCR 완료! (인식률: ${confidence.toFixed(2)}%)`, 'success');

  } catch (error) {
    console.error('OCR 오류:', error);
    updateStatus(`❌ OCR 실패: ${error.message}`, 'error');
  }
}

/**
 * 영역 선택 OCR 실행
 */
async function performRegionOCR() {
  const videoElement = player.el().querySelector('video');

  // 선택 영역 계산
  const overlayRect = overlay.getBoundingClientRect();
  const x = Math.min(selectionStart.x, selectionEnd.x);
  const y = Math.min(selectionStart.y, selectionEnd.y);
  const width = Math.abs(selectionEnd.x - selectionStart.x);
  const height = Math.abs(selectionEnd.y - selectionStart.y);

  const region = { x, y, width, height };

  // OCR 실행
  await performOCR(videoElement, region);

  // 선택 박스 유지 (결과 확인 후 수동으로 모드 전환)
  // resetSelection();
}

/**
 * 결과 표시
 */
function displayResults(rawText, confidence, codeBlocks) {
  // 인식률
  document.getElementById('confidence').textContent = `${confidence.toFixed(2)}%`;

  // 라인 넘버 분석
  const analysis = analyzeLineNumbers(rawText);
  const cleanedText = cleanCodeText(rawText);

  // 전체 텍스트 (정제 전/후 비교)
  document.getElementById('raw-text').innerHTML = `
    <div style="margin-bottom: 15px;">
      <strong style="color: #FFC107;">원본 (라인 넘버 포함):</strong><br>
      <em style="color: #888; font-size: 11px;">
        총 ${analysis.totalLines}줄 | 라인넘버: ${analysis.linesWithNumbers}줄 | 순수코드: ${analysis.linesWithoutNumbers}줄
      </em>
      <pre style="max-height: 150px; overflow-y: auto; background: #0a0a0a; padding: 10px; margin-top: 5px;">${escapeHtml(rawText) || '(텍스트 없음)'}</pre>
    </div>
    <div>
      <strong style="color: #4CAF50;">정제 후 (라인 넘버 제거):</strong>
      <pre style="max-height: 150px; overflow-y: auto; background: #0a0a0a; padding: 10px; margin-top: 5px;">${escapeHtml(cleanedText) || '(텍스트 없음)'}</pre>
    </div>
  `;

  // 코드 블록
  const codeBlocksContainer = document.getElementById('code-blocks');
  if (codeBlocks.length > 0) {
    codeBlocksContainer.innerHTML = codeBlocks.map((block, i) =>
        `<div class="code-block">
        <strong>코드 블록 ${i + 1}:</strong> <em style="color: #888; font-size: 11px;">(${block.length} chars)</em><br>
        <pre>${escapeHtml(block)}</pre>
      </div>`
    ).join('');
  } else {
    codeBlocksContainer.innerHTML = '<em>코드 블록이 감지되지 않았습니다.</em>';
  }
}

/**
 * HTML 이스케이프
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ==========================================
// 초기화 완료 로그
// ==========================================
console.log('✅ Video OCR Prototype 초기화 완료');
console.log('📷 OCR 버튼을 눌러 현재 프레임을 캡처하고 텍스트를 추출하세요.');