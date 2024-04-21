FROM pytorch/pytorch:2.2.2-cuda11.8-cudnn8-devel

COPY src /app
WORKDIR /app

RUN pip install -r requirements.txt

CMD ["python", "main.py"]