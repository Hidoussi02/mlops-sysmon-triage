# Set this to the SAME major.minor Python version as your laptop (python --version),
# so the saved model loads without surprises.
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# XGBoost needs the OpenMP library, which is missing from "slim" images
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Least privilege: create a normal user with no admin rights
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Install dependencies first (Docker caches this layer if requirements don't change)
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 --retries=10 -r requirements.txt

# Only the API code goes in the image; the model is mounted at run time
COPY app.py .

USER appuser
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"

# gunicorn is a production-grade server (Flask's built-in one is for development only)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "app:app"]