FROM python:3.10.14-slim

COPY src /app
COPY dist/swagger-ui /app/dist
WORKDIR /app

RUN pip install -r requirements/mongo_client.txt
RUN sed -i 's|"https.*swagger-ui.css"|"/static/swagger-ui.css"|g' /usr/local/lib/python3.10/site-packages/fastapi/openapi/docs.py &&\
    sed -i 's|"https.*swagger-ui-bundle.js"|"/static/swagger-ui-bundle.js"|g' /usr/local/lib/python3.10/site-packages/fastapi/openapi/docs.py

CMD ["python", "run_clients.py", "-c", "mongo"]