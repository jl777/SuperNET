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
        sh '''cargo build --bin mm2-nop --features nop
cargo build -vv
cargo test
cargo test --package etomicrs'''
      }
    }
    stage('Test Trade') {
      steps {
        sh '''cargo test -- --ignored'''
      }
    }
  }
}