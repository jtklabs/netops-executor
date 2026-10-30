FROM ubuntu:24.04
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
# Ubuntu's Python 3.12 is externally managed (PEP 668), so the service runs from its own venv.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv
WORKDIR /app
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY netops_executor ./netops_executor
RUN pip install --no-cache-dir --no-deps . \
    && useradd --uid 10001 --create-home netopsexecutor \
    && mkdir /data /backups && chown 10001:10001 /data /backups
USER 10001:10001
EXPOSE 8080
CMD ["netops-executor", "serve", "--host", "0.0.0.0"]
