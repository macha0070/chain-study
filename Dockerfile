# chain-study — 追加パッケージなしで動くので、ベースイメージだけで完結する。
# pip install が 1 行も無いのは、リポジトリの方針（標準ライブラリのみ）の帰結。
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PORT=8000

WORKDIR /app

# 非 root で動かす。ローカル実験用でも、既定を安全側に寄せておく。
RUN useradd --create-home --uid 10001 lab
COPY --chown=lab:lab chain/ ./chain/
COPY --chown=lab:lab web/ ./web/
COPY --chown=lab:lab tests/ ./tests/
COPY --chown=lab:lab README.md ./
COPY --chown=lab:lab docs/ ./docs/
USER lab

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/health', timeout=2).status==200 else 1)"

CMD ["python", "web/server.py"]
