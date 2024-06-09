FROM pytorch/pytorch:2.2.2-cuda11.8-cudnn8-devel

COPY src /app
COPY dist/swagger-ui /app/dist
WORKDIR /app

RUN pip install -r requirements/text_classification.txt
RUN sed -i 's|"https.*swagger-ui.css"|"/static/swagger-ui.css"|g' /opt/conda/lib/python3.10/site-packages/fastapi/openapi/docs.py &&\
    sed -i 's|"https.*swagger-ui-bundle.js"|"/static/swagger-ui-bundle.js"|g' /opt/conda/lib/python3.10/site-packages/fastapi/openapi/docs.py

CMD ["python", "run_clients.py", "-c", "tc"]