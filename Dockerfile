FROM python:3.10

RUN apt-get update && apt-get install -y nmap

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

CMD ["python", "main.py"]