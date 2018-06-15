#!/bin/bash
docker-compose exec -T clientnode ./setpassphrase
sleep 5
docker-compose exec -T clientnode ./enable
sleep 5
docker-compose exec -T seednode ./setpassphrase
sleep 5
docker-compose exec -T seednode ./enable
sleep 5
docker-compose exec -T seednode ./sell_BEER_OTHER $1
sleep 5
docker-compose exec -T clientnode ./buy_BEER_OTHER $1