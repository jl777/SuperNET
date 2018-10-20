#!/bin/bash
sleep 5
docker-compose exec -T clientnode ./enable
sleep 3
docker-compose exec -T seednode ./enable
sleep 3
docker-compose exec -T clientnode ./buy_BEER_OTHER $1
sleep 3
docker-compose exec -T seednode ./sell_BEER_OTHER $1