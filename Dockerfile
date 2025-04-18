FROM python:3.9
RUN apt-get update && apt-get install -y nmap
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "src/webapp.py"]