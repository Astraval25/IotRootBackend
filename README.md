
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
```
