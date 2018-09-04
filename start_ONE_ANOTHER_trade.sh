#!/bin/bash
sleep 5
docker-compose exec -T clientnode ./enable
sleep 3
docker-compose exec -T seednode ./enable
sleep 3
docker-compose exec -T seednode ./sell_ONE_ANOTHER $1 $2
sleep 3
docker-compose exec -T clientnode ./buy_ONE_ANOTHER $1 $2
