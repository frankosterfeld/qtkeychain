pipeline {
    agent none
    parameters {
        string(name: 'BRANCH', defaultValue: 'master', description: 'Branch to build from')
        booleanParam(name: 'PUBLISH', defaultValue: false, description: 'Publish artifact to artifactory online')
        booleanParam(name: 'USE_TIMESTAMP', defaultValue: false, description: 'Add timestamp as a prefix to the artifact version')
    }
    stages {
        stage('Build'){
            parallel {
                stage('Build Osx, Simulator, Device') {
                    agent { label 'osx' }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'artifactory-online-publish', passwordVariable: 'artifactory_password', usernameVariable: 'artifactory_user')]) {
                            sh "./gradlew buildDevice buildOsx buildSimulator copyLib -Pqt_core=/Qt/5.10.0 -Partifactory_user=$artifactory_user -Partifactory_password=$artifactory_password -Partifactory_contextUrl=https://qliktech.jfrog.io/qliktech --info --no-daemon"
                            stash includes: "include/*", name: 'build-ios-include'
                            stash includes: "lib/*", name: 'build-ios-lib'
                        }
                        cleanWs()
                    }
                }
                stage('Build Android') {
                    agent { docker { image 'qliktech-docker.jfrog.io/qsm-build-env:latest' } }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'artifactory-online-publish', passwordVariable: 'artifactory_password', usernameVariable: 'artifactory_user')]) {
                            sh './gradlew buildAndroid buildAndroidx86 copyLibAndroid -Pqt_core=${QT_HOME}/${QT_VERSION} -Partifactory_user=$artifactory_user -Partifactory_password=$artifactory_password -Partifactory_contextUrl=https://qliktech.jfrog.io/qliktech --info --no-daemon'
                            sh 'zip build-android-lib lib/*'
                            stash includes: "build-android-lib.zip", name: 'build-android-lib'
                            //Temporary archive adnroid libs separately
                            archiveArtifacts 'build-android/*.a'
                            archiveArtifacts 'build-androidx86/*.a'

                        }
                        cleanWs()
                    }

                }
            }
        }
        stage('Package & Publish') {
            agent { label 'osx' }
            stages{
                stage('Package') {
                    steps {
                        unstash 'build-android-lib'
                        unstash 'build-ios-lib'
                        unstash 'build-ios-include'
                        sh 'unzip build-android-lib.zip'
                        withCredentials([usernamePassword(credentialsId: 'artifactory-online-publish', passwordVariable: 'artifactory_password', usernameVariable: 'artifactory_user')]) {
                            sh "./gradlew packageLib -Puse_timestamp=${USE_TIMESTAMP} -Pqt_core=/Qt/5.10.0 -Partifactory_user=$artifactory_user -Partifactory_password=$artifactory_password -Partifactory_contextUrl=https://qliktech.jfrog.io/qliktech -PbranchName=$BRANCH -Ppublish_android=true -Ppublish_ios=true --info --no-daemon"
                        }
                        archiveArtifacts 'dist/*.zip'
                    }
                }

                stage('Publish') {
                    when { environment name: 'PUBLISH', value: 'true' }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'artifactory-online-publish', passwordVariable: 'artifactory_password', usernameVariable: 'artifactory_user')]) {
                            sh "./gradlew upload -Puse_timestamp=${USE_TIMESTAMP} -Pqt_core=/Qt/5.10.0 -Partifactory_user=$artifactory_user -Partifactory_password=$artifactory_password -Partifactory_contextUrl=https://qliktech.jfrog.io/qliktech -PbranchName=$BRANCH -Ppublish_android=true -Ppublish_ios=true --info --no-daemon"
                        }
                    }
                }
                stage('Cleanup') {
                    steps {
                        cleanWs()
                    }
                }
            }
        }
    }
}
