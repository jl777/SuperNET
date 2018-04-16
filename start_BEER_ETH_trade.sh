#!/bin/bash
docker-compose exec -T clientnode ./setpassphrase
sleep 1
docker-compose exec -T clientnode ./enable
sleep 1
docker-compose exec -T seednode ./setpassphrase
sleep 1
docker-compose exec -T seednode ./enable
sleep 1
docker-compose exec -T seednode ./sell_BEER_ETH
sleep 3
docker-compose exec -T clientnode ./buy_BEER_ETH