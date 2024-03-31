FROM python:3.10-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r analyzer/requirements.txt

ENV CONF_PATH ""

CMD python flan_analyzer.py -c ${CONF_PATH}