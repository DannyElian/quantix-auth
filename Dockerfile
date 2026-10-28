FROM python:3.11-slim
WORKDIR /app
COPY server.py /app/server.py
ENV PORT=8787
EXPOSE 8787
CMD ["python3", "server.py"]
