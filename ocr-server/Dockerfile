FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# EasyOCR + OpenCV 의존 시스템 라이브러리
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 \
        libgl1 \
        libsm6 \
        libxrender1 \
        libxext6 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
        torch==2.2.2+cpu \
        torchvision==0.17.2+cpu
RUN pip install --no-cache-dir -r requirements.txt

# 이미지 빌드 시 EasyOCR 영어 모델 다운로드 → 컨테이너 실행 후 대기 없음

COPY app.py .
RUN mkdir -p /app/.EasyOCR

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

CMD ["python", "app.py"]
