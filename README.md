
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