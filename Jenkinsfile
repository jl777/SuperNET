pipeline {
  agent {
    docker {
      image 'artempikulin/cmake-ubuntu'
    }
    
  }
  stages {
    stage('Build') {
      steps {
        sh '''mkdir build
cd build
cmake ..
cmake --build . --target marketmaker-testnet'''
      }
    }
  }
}