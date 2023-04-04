FROM python:3-alpine

COPY requirements.txt discord_relay.py ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "./discord_relay.py" ]
