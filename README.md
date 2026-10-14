
# iotroot Backend Deployment Guide

## 1. Clone and Prepare Source

```bash
cd /var/www/domains/iotroot.astraval.com/IotRootBackend
chmod +x gradlew
git pull
```

## 2. Build the Application

```bash
./gradlew clean build -x test
```

## 3. Deploy JAR

```bash
sudo cp /var/www/domains/iotroot.astraval.com/IotRootBackend/build/libs/iotrootbackend-0.0.1-SNAPSHOT.jar /var/www/iotroot/iotroot.jar
```
```bash
# Restart the application after DB setup
sudo systemctl restart iotroot
sudo journalctl -u iotroot -f
```
---

## 4. VerneMQ Usage Tracking Webhook

Set these environment variables for backend:

```bash
VERNEMQ_WEBHOOK_SECRET=change_this_secret
VERNEMQ_ADMIN_PATH=/opt/vernemq/bin/vmq-admin
VERNEMQ_BROKER_HOST=iotroot.astraval.com
VERNEMQ_BROKER_PORT=1883
```

Configure VerneMQ webhook (example endpoint):

```ini
plugins.vmq_webhooks = on
vmq_webhooks.pool_timeout = 1000
vmq_webhooks.pool_max_connections = 100

vmq_webhooks.usage_publish.hook = on_publish
vmq_webhooks.usage_publish.endpoint = http://127.0.0.1:8090/api/vernemq/webhooks/usage?secret=change_this_secret
vmq_webhooks.usage_publish.base64encode = off

vmq_webhooks.usage_deliver.hook = on_deliver
vmq_webhooks.usage_deliver.endpoint = http://127.0.0.1:8090/api/vernemq/webhooks/usage?secret=change_this_secret
vmq_webhooks.usage_deliver.base64encode = off

vmq_webhooks.usage_publish_m5.hook = on_publish_m5
vmq_webhooks.usage_publish_m5.endpoint = http://127.0.0.1:8090/api/vernemq/webhooks/usage?secret=change_this_secret
vmq_webhooks.usage_publish_m5.base64encode = off

vmq_webhooks.usage_deliver_m5.hook = on_deliver_m5
vmq_webhooks.usage_deliver_m5.endpoint = http://127.0.0.1:8090/api/vernemq/webhooks/usage?secret=change_this_secret
vmq_webhooks.usage_deliver_m5.base64encode = off
```

## Stored JSON data

Create a device publish rule under `/iot/store/{userId}/#`. Every valid JSON payload published to a concrete matching topic is persisted once from the `on_publish` webhook. Delivery hooks are used for usage accounting only and do not create stored-data rows.

On Windows Command Prompt, escape JSON double quotes because single quotes are transmitted as payload characters:

```bat
mosquitto_pub -h iotroot.astraval.com -p 1883 -u USERNAME -P PASSWORD -i CLIENT_ID -t /iot/store/USER_ID/status -m "{\"value\":1}" -q 1
```

PowerShell, Bash, and similar shells can use `-m '{"value":1}'`.

Manage read-only integration keys from the dashboard or with the authenticated `/api/api-keys` endpoints. The complete key is returned only when it is created. Use it with:

```bash
curl -H "X-API-Key: iotr_live_REPLACE_ME" \
  "https://iotroot.astraval.com/api/v1/store/messages"
```

The data endpoint returns the most recent hour by default. It accepts `from`, `to`, `deviceId`, `topic`, `topicPrefix`, `page`, and `size` query parameters. Date values use ISO-8601 instants and a query range may not exceed 31 days.

Notes:
- Some VerneMQ 2.0 builds do not support webhook custom headers, so the shared secret is passed by query parameter.
- The backend endpoint returns VerneMQ-compatible responses (`{}` for publish hooks and `{"result":"ok"}` for deliver hooks).

Restart VerneMQ and backend:

```bash
sudo systemctl restart vernemq
sudo systemctl restart iotroot
```

Usage APIs:

```bash
GET /api/devices/{id}/usage/summary
GET /api/devices/{id}/usage/buckets
GET /api/devices/usage/summary
GET /api/usage/overview?from=...&to=...
```
