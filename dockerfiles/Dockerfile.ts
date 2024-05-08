FROM pytorch/pytorch:2.2.2-cuda11.8-cudnn8-devel

COPY src /app
WORKDIR /app

RUN pip install -r requirements.txt
RUN sed -i 's|"https.*swagger-ui.css"|"/static/swagger-ui.css"|g' /usr/local/lib/python3.10/site-packages/fastapi/openapi/docs.py &&\
    sed -i 's|"https.*swagger-ui-bundle.js"|"/static/swagger-ui-bundle.js"|g' /usr/local/lib/python3.10/site-packages/fastapi/openapi/docs.py

CMD ["python", "main.py"]