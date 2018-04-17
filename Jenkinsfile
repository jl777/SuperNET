pipeline {
  agent any
  stages {
    stage('Prepare') {
      steps {
        sh '''cp -r /root/.env.client .env.client
cp -r /root/.env.seed .env.seed'''
      }
    }
    stage('Build') {
      steps {
        sh '''git submodule update --init --recursive
rm -rf build
mkdir build
cd build
cmake ..
cmake --build . --target marketmaker-testnet'''
      }
    }
    stage('Trade') {
      steps {
        sh '''docker-compose build
docker-compose up -d
./start_BEER_ETH_trade.sh
timeout 300 grep -q "SWAP completed" <(docker-compose logs -f clientnode)
timeout 300 grep -q "SWAP completed" <(docker-compose logs -f seednode)
docker-compose down'''
      }
    }
  }
}