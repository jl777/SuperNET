pipeline {
  agent {
    docker {
      image 'artempikulin/cmake-ubuntu'
      args '-v .:/home/SuperNET -w /home/SuperNET'
    }
    
  }
  stages {
    stage('Build') {
      steps {
        build 'Cmake'
      }
    }
  }
}