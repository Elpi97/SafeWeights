# Optional CLI container for GitHub Packages (ghcr.io).
# GUI still runs natively on Windows VE via `python main.py`.
FROM python:3.14-slim

LABEL org.opencontainers.image.source="https://github.com/Elpi97/SafeWeights"
LABEL org.opencontainers.image.description="SafeWeights static AI model scanner (CLI)"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY safewights ./safewights
COPY main.py ./

RUN pip install --no-cache-dir .

ENTRYPOINT ["safewights"]
CMD ["--help"]
