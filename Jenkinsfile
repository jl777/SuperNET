pipeline {
  agent {
    docker {
      image 'artempikulin/cmake-ubuntu'
    }
    
  }
  stages {
    stage('Build') {
      steps {
        sh 'docker run -v .:/home/SuperNET -w /home/SuperNET --rm artempikulin/cmake-ubuntu'
      }
    }
  }
}