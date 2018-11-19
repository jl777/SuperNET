pipeline {
  agent any
  options { disableConcurrentBuilds() }
  stages {
    stage('Prepare') {
      steps {
        sh '''rustup install stable'''
      }
    }
    stage('Build') {
      steps {
        sh '''
export CC=gcc-5 CXX=g++-5
cargo build -vv
cargo test
cargo test --package etomicrs
'''
      }
    }
    stage('Test Trade') {
      steps {
        sh '''cargo test -- --ignored'''
      }
    }
  }
}