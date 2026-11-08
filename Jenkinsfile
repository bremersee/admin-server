pipeline {
  agent {
    label 'jdk25 && maven && docker'
  }
  environment {
    CODECOV_TOKEN = credentials('admin-server-codecov-token')
    BRANCH_NAME = "${GIT_BRANCH.split("/").size() > 1 ? GIT_BRANCH.split("/")[1] : GIT_BRANCH}"
    NAME = 'admin'
    NON_SECURE_PORT = 8080
    PROFILES = 'eureka-client,mail,ldap-with-bind,ldap-auth,remember-me'
    DOCKER_IMAGE = 'bremersee/admin-server'
    DOCKER_HOSTS = 'app1 app2'
    DOCKER_PUSH = true
    DEPLOY_ON_APP_SERVER = true
    SITE = false
    CLEAN = true
  }
  tools {
    jdk 'jdk25'
    maven 'm3'
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '8', artifactNumToKeepStr: '8'))
  }
  stages {
    stage('Tools') {
      steps {
        sh 'java -version'
        sh 'mvn -B --version'
        sh 'echo $BRANCH_NAME'
      }
    }
    stage('Build') {
      steps {
        sh 'mvn -B -P build-system clean package'
      }
      post {
        always {
          junit '**/surefire-reports/*.xml'
          recordCoverage(
              tools: [[parser: 'JACOCO', pattern: '**/coverage-reports/*.exec']],
              sourceCodeRetention: 'LAST_BUILD'
          )
        }
      }
    }
    stage('Site') {
      when {
        allOf {
          environment name: 'SITE', value: 'true'
          anyOf {
            branch 'develop'
            branch 'main'
            branch 'feature/*'
            branch 'bugfix/*'
          }
        }
      }
      steps {
        sh '''
          mvn -B -P build-system,gh-pages-site site site:stage
          git clone -b gh-pages git@github.com:bremersee/$NAME.git target/gh-pages
          cp -rf target/staging/* target/gh-pages
          git -C target/gh-pages add .
          git -C target/gh-pages commit -m "Maven site"
          git -C target/gh-pages push
          rm -rf target/gh-pages
        '''
      }
      post {
        always {
          sh 'curl -s https://codecov.io/bash | bash -s - -t ${CODECOV_TOKEN}'
        }
      }
    }
    stage('Docker Push') {
      when {
        allOf {
          environment name: 'DOCKER_PUSH', value: 'true'
          anyOf {
            branch 'develop'
            branch 'main'
          }
        }
      }
      steps {
        withCredentials([
          usernamePassword(
            credentialsId: 'dockerhub',
            usernameVariable: 'DOCKER_USER',
            passwordVariable: 'DOCKER_SECRET')
        ]) {
          sh '''
            #!/bin/bash
            MVN_VERSION=\$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
            TAG=\$MVN_VERSION
            LATEST="latest"
            echo "Building and pushing docker image $DOCKER_IMAGE:\$TAG"
            mvn -B -P build-system -DskipTests clean package
            docker context use default
            docker login -u $DOCKER_USER -p $DOCKER_SECRET
            docker run --privileged --rm tonistiigi/binfmt --install all
            docker \
              buildx \
              build \
              -t $DOCKER_IMAGE:\$TAG \
              -t $DOCKER_IMAGE:\$LATEST \
              -f Dockerfile \
              --platform=linux/amd64,linux/arm64 \
              --build-arg port=$NON_SECURE_PORT \
              --push \
              .
            docker image prune -a -f
          '''
        }
      }
    }
    stage('Deploy On App Server') {
      when {
        allOf {
          environment name: 'DEPLOY_ON_APP_SERVER', value: 'true'
          anyOf {
            branch 'develop'
            branch 'main'
          }
        }
      }
      steps {
        withCredentials([
          usernamePassword(
            credentialsId: 'config-server-client',
            usernameVariable: 'CONFIG_USER',
            passwordVariable: 'CONFIG_SECRET')
        ]) {
          sh '''
            #!/bin/bash
            sleep 10
            MVN_VERSION=\$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
            TAG=\$MVN_VERSION
            LATEST="latest"
            for DOCKER_HOST in $DOCKER_HOSTS; do
              CONTAINER_ID=\$(docker \
                -H ssh://root@\$DOCKER_HOST \
                ps -aqf "name=^$NAME")
              echo "Container id is \$CONTAINER_ID"
              if [ -z "\$CONTAINER_ID" ]; then
                echo "No $NAME container is running."
              else
                echo "Stopping $NAME container with ID \$CONTAINER_ID."
                docker \
                  -H ssh://root@\$DOCKER_HOST \
                  stop \$CONTAINER_ID
                sleep 10
                docker \
                  -H ssh://root@\$DOCKER_HOST \
                  rm \$CONTAINER_ID
                sleep 10
              fi
              docker -H ssh://root@\$DOCKER_HOST pull $DOCKER_IMAGE:\$TAG
              docker \
                -H ssh://root@\$DOCKER_HOST \
                run \
                --detach \
                --tty \
                --interactive \
                --name=$NAME \
                --network=host \
                --restart=unless-stopped \
                -e ACTIVE_PROFILES=\$DOCKER_HOST,$PROFILES \
                -e CONFIG_CLIENT_ENABLED='true' \
                -e CONFIG_URI='https://config.eixe.bremersee.org' \
                -e CONFIG_USER=$CONFIG_USER \
                -e CONFIG_PASSWORD=$CONFIG_SECRET \
                -e CONFIG_LABEL=$BRANCH_NAME \
                -e SERVER_PORT=$NON_SECURE_PORT \
                $DOCKER_IMAGE:\$TAG
              sleep 10
              docker \
                -H ssh://root@\$DOCKER_HOST \
                image prune -a -f
            done
          '''
        }
      }
    }
    stage('Clean') {
      when {
        environment name: 'CLEAN', value: 'true'
      }
      steps {
        sh 'mvn -B clean'
      }
    }
  }
}

pipeline {
  agent none
  environment {
    SERVICE_NAME = 'admin-server'
    DOCKER_IMAGE = 'bremersee/admin-server'
    DEV_TAG = 'snapshot'
    PROD_TAG = 'latest'
    PUSH_SNAPSHOT = false
    PUSH_RELEASE = true
    DEPLOY_SNAPSHOT = false
    DEPLOY_RELEASE = true
    SNAPSHOT_SITE = false
    RELEASE_SITE = true
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '8', artifactNumToKeepStr: '8'))
  }
  stages {
    stage('Test') {
      agent {
        label 'maven'
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      when {
        not {
          branch 'feature/*'
        }
      }
      steps {
        sh 'java -version'
        sh 'mvn -B --version'
        sh 'mvn -B clean test'
      }
      post {
        always {
          junit '**/surefire-reports/*.xml'
          jacoco(
              execPattern: '**/coverage-reports/*.exec'
          )
        }
      }
    }
    stage('Push snapshot') {
      agent {
        label 'maven'
      }
      when {
        allOf {
          branch 'develop'
          environment name: 'PUSH_SNAPSHOT', value: 'true'
        }
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      steps {
        sh '''
          mvn -B -DskipTests -Ddockerfile.skip=false clean package dockerfile:push
          mvn -B -DskipTests -Ddockerfile.skip=false -Ddockerfile.tag=snapshot clean package dockerfile:push
          docker system prune -a -f
        '''
      }
    }
    stage('Push release') {
      agent {
        label 'maven'
      }
      when {
        allOf {
          branch 'master'
          environment name: 'PUSH_RELEASE', value: 'true'
        }
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      steps {
        sh '''
          mvn -B -DskipTests -Ddockerfile.skip=false clean package dockerfile:push
          mvn -B -DskipTests -Ddockerfile.skip=false -Ddockerfile.tag=latest clean package dockerfile:push
          docker system prune -a -f
        '''
      }
    }
    stage('Deploy on dev-swarm') {
      agent {
        label 'dev-swarm'
      }
      when {
        allOf {
          branch 'develop'
          environment name: 'DEPLOY_SNAPSHOT', value: 'true'
        }
      }
      steps {
        sh '''
          if docker service ls | grep -q ${SERVICE_NAME}; then
            echo "Updating service ${SERVICE_NAME} with docker image ${DOCKER_IMAGE}:${DEV_TAG}."
            docker service update --image ${DOCKER_IMAGE}:${DEV_TAG} ${SERVICE_NAME}
          else
            echo "Creating service ${SERVICE_NAME} with docker image ${DOCKER_IMAGE}:${DEV_TAG}."
            chmod 755 docker-swarm/service.sh
            docker-swarm/service.sh "${DOCKER_IMAGE}:${DEV_TAG}" "swarm,dev"
          fi
        '''
      }
    }
    stage('Deploy on prod-swarm') {
      agent {
        label 'prod-swarm'
      }
      when {
        allOf {
          branch 'master'
          environment name: 'DEPLOY_RELEASE', value: 'true'
        }
      }
      steps {
        sh '''
          if docker service ls | grep -q ${SERVICE_NAME}; then
            echo "Updating service ${SERVICE_NAME} with docker image ${DOCKER_IMAGE}:${PROD_TAG}."
            docker service update --image ${DOCKER_IMAGE}:${PROD_TAG} ${SERVICE_NAME}
          else
            echo "Creating service ${SERVICE_NAME} with docker image ${DOCKER_IMAGE}:${PROD_TAG}."
            chmod 755 docker-swarm/service.sh
            docker-swarm/service.sh "${DOCKER_IMAGE}:${PROD_TAG}" "swarm,prod"
          fi
        '''
      }
    }
    stage('Deploy snapshot site') {
      agent {
        label 'maven'
      }
      environment {
        CODECOV_TOKEN = credentials('admin-server-codecov-token')
      }
      when {
        allOf {
          branch 'develop'
          environment name: 'SNAPSHOT_SITE', value: 'true'
        }
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      steps {
        sh 'mvn -B clean site-deploy'
      }
      post {
        always {
          sh 'curl -s https://codecov.io/bash | bash -s - -t ${CODECOV_TOKEN}'
        }
      }
    }
    stage('Deploy release site') {
      agent {
        label 'maven'
      }
      environment {
        CODECOV_TOKEN = credentials('admin-server-codecov-token')
      }
      when {
        allOf {
          branch 'master'
          environment name: 'RELEASE_SITE', value: 'true'
        }
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      steps {
        sh 'mvn -B -P gh-pages-site clean site site:stage scm-publish:publish-scm'
      }
      post {
        always {
          sh 'curl -s https://codecov.io/bash | bash -s - -t ${CODECOV_TOKEN}'
        }
      }
    }
    stage('Test feature') {
      agent {
        label 'maven'
      }
      when {
        branch 'feature/*'
      }
      tools {
        jdk 'jdk11'
        maven 'm3'
      }
      steps {
        sh 'java -version'
        sh 'mvn -B --version'
        sh 'mvn -B -P feature,allow-features clean test'
      }
      post {
        always {
          junit '**/surefire-reports/*.xml'
          jacoco(
              execPattern: '**/coverage-reports/*.exec'
          )
        }
      }
    }
  }
}
