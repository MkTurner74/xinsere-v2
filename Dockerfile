# Xinsere hosted demo (v2). Build context = repo root.
#   docker build -t xinsere-demo .
#   docker run -p 8000:8000 -v xinsere-data:/data -e XINSERE_PRIVATE_KEY=0x... xinsere-demo
FROM python:3.12-slim

WORKDIR /app

# Deps first for layer caching.
COPY demo/requirements.txt ./demo/requirements.txt
RUN pip install --no-cache-dir -r demo/requirements.txt

# App + the pipeline package it imports from ../lambdas/pipeline.
COPY demo/ ./demo/
COPY lambdas/pipeline/ ./lambdas/pipeline/

WORKDIR /app/demo

# Persistent data (users.db, encrypted fragments, index) lives here — mount a volume.
ENV XINSERE_DATA_DIR=/data
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
