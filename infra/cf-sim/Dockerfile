FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
# Sirve en el puerto 80 interno para que el alias `dvwa-cf` responda a
# http://dvwa-cf (puerto HTTP por defecto). El contenedor corre como root
# por defecto en python:3.12-slim, así que uvicorn puede bindar a 80.
EXPOSE 80
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]
