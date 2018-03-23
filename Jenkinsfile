pipeline {
  agent {
    docker {
      image 'artempikulin/cmake-ubuntu'
    }
    
  }
  stages {
    stage('Build') {
      steps {
        sh '''rm -rf build
mkdir build
cd build
cmake ..
cmake --build . --target marketmaker-testnet'''
      }
    }
  }
}