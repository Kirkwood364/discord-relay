FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Run as a non-root user; /data holds all persistent state.
RUN useradd --create-home --uid 1000 relay \
    && mkdir -p /data && chown relay:relay /data
USER relay

ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]
