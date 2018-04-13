#!/bin/bash
docker-compose exec clientnode ./setpassphrase
sleep 1
docker-compose exec clientnode ./enable
sleep 1
docker-compose exec seednode ./setpassphrase
sleep 1
docker-compose exec seednode ./enable
sleep 1
docker-compose exec seednode ./sell_BEER_ETH
sleep 3
docker-compose exec clientnode ./buy_BEER_ETH