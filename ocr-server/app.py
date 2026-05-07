"""
DevPath OCR Server
EasyOCR 기반 코드 인식 서버 (포트 5000)

POST /ocr
  Request : { "image": "<base64 PNG>" }
  Response: { "text": "...", "confidence": 0.95, "lines": [...] }

GET /health
  Response: { "status": "ok" }
"""

import base64
import io
import logging
import os

import cv2
import easyocr
import numpy as np
from flask import Flask, jsonify, request
from PIL import Image, ImageFilter, ImageOps

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── EasyOCR Reader 초기화 (컨테이너 시작 시 1회, 모델 캐싱) ──────────────
log.info("EasyOCR 모델 로딩 중...")
reader = easyocr.Reader(
    ["en"],
    gpu=False,
    model_storage_directory="/app/.EasyOCR",
    download_enabled=True,
)
log.info("EasyOCR 모델 로딩 완료")


# ── 이미지 전처리 ─────────────────────────────────────────────────────────

def decode_image(b64: str) -> Image.Image:
    """base64 문자열 → PIL Image"""
    data = base64.b64decode(b64)
    return Image.open(io.BytesIO(data)).convert("RGB")


def preprocess(img: Image.Image) -> np.ndarray:
    """
    코드 스크린샷 OCR 최적화 전처리:
      1. 그레이스케일
      2. 다크 테마 반전 (히스토그램 기반 — 어두운 픽셀 비율 40% 이상)
      3. 업스케일 (짧은 변 기준 — 텍스트 높이 확보)
      4. UnsharpMask 선명화 (획 경계 강조)
      5. Adaptive Threshold 이진화 (지역 조명 차이 대응)
    """
    arr = np.array(img.convert("L"))

    # 다크 테마 반전: 어두운 픽셀(< 50) 비율이 40% 초과면 반전
    if np.sum(arr < 50) / arr.size > 0.4:
        arr = 255 - arr

    # 업스케일: 짧은 변이 작을수록 고배율 확대
    h, w = arr.shape
    short_side = min(w, h)
    if short_side < 300:
        scale = 3
    elif short_side < 600:
        scale = 2
    else:
        scale = 1

    if scale > 1:
        arr = cv2.resize(arr, (w * scale, h * scale), interpolation=cv2.INTER_CUBIC)

    # UnsharpMask 선명화 (이진화 전 경계 강조)
    pil = Image.fromarray(arr)
    pil = pil.filter(ImageFilter.UnsharpMask(radius=1, percent=120, threshold=3))
    arr = np.array(pil)

    # Adaptive Threshold 이진화 (지역 조명 차이·그림자 대응)
    arr = cv2.adaptiveThreshold(
        arr,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        blockSize=15,
        C=10,
    )

    return arr


# ── 엔드포인트 ────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/ocr", methods=["POST"])
def ocr():
    body = request.get_json(silent=True)
    if not body or "image" not in body:
        return jsonify({"error": "image 필드가 필요합니다."}), 400

    try:
        img   = decode_image(body["image"])
        arr   = preprocess(img)

        # EasyOCR 인식
        results = reader.readtext(
            arr,
            detail=1,
            paragraph=False,
            # 코드 인식에 유리한 옵션
            width_ths=0.5,       # 같은 줄 텍스트 합치기 임계값
            add_margin=0.05,
        )

        lines       = [text for (_, text, _) in results]
        confidences = [conf for (_, _, conf) in results]

        text       = "\n".join(lines)
        avg_conf   = (sum(confidences) / len(confidences)) if confidences else 0.0

        log.info("OCR 완료 — %d줄, 평균 신뢰도 %.2f", len(lines), avg_conf)

        return jsonify({
            "text":       text,
            "confidence": round(avg_conf, 4),
            "lines":      lines,
        })

    except Exception as exc:  # noqa: BLE001
        log.exception("OCR 처리 중 오류")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
