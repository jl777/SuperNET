pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh '''echo $HOME
git submodule update --init --recursive
rm -rf build
mkdir build
cd build
cmake ..
cmake --build . --target marketmaker-testnet'''
      }
    }
  }
}