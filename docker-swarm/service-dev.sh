#!/usr/bin/env sh
docker service create \
  --replicas 1 \
  --name admin-server \
  --network proxy \
  --publish 8080:80 \
  --secret config-server-client-user \
  --secret config-server-client-user-password \
  --mount type=volume,source=common-log,target=/opt/log \
  --restart-delay 10s \
  --restart-max-attempts 10 \
  --restart-window 60s \
  --update-delay 10s \
  --constraint 'node.role == manager' \
  -e APPLICATION_NAME='admin' \
  -e ACTIVE_PROFILES='swarm,dev' \
  -e CONFIG_CLIENT_ENABLED='true' \
  -e CONFIG_URI='http://config-server' \
  -e CONFIG_USER_FILE='/run/secrets/config-server-client-user' \
  -e CONFIG_PASSWORD_FILE='/run/secrets/config-server-client-user-password' \
  -e CONFIG_CLIENT_FAIL_FAST='true' \
  -e CONFIG_RETRY_INIT_INTERVAL='3000' \
  -e CONFIG_RETRY_MAX_INTERVAL='4000' \
  -e CONFIG_RETRY_MAX_ATTEMPTS='8' \
  -e CONFIG_RETRY_MULTIPLIER='1.1' \
  -e SERVER_PORT='80' \
  bremersee/admin-server:snapshot
