#!/usr/bin/env bash

set -o errexit   # abort on nonzero exitstatus
set -o nounset   # abort on unbound variable
set -o pipefail  # don't hide errors within pipes

shopt -s globstar
shopt -s nullglob

# Using shards to optimise tests
# In the future we can incorporate test durations rather than using
# a static value for the parallel keyword

# Number of parallel shards to split the test suite into
CI_PARALLEL=2

# Quote the heredoc to prevent shell expansion
cat << "EOF"
variables:
  GIT_SUBMODULE_STRATEGY: "recursive"
  GH_PROJECT_PATH: "MatrixAI/${CI_PROJECT_NAME}"
  GH_PROJECT_URL: "https://${GITHUB_TOKEN}@github.com/${GH_PROJECT_PATH}.git"
  # Cache .npm
  npm_config_cache: "${CI_PROJECT_DIR}/tmp/npm"
  # Prefer offline node module installation
  npm_config_prefer_offline: "true"
  # Homebrew cache only used by macos runner
  HOMEBREW_CACHE: "${CI_PROJECT_DIR}/tmp/Homebrew"

default:
  interruptible: true
  before_script:
    # Replace this in windows runners that use powershell
    # with `mkdir -Force "$CI_PROJECT_DIR/tmp"`
    - mkdir -p "$CI_PROJECT_DIR/tmp"

# Cached directories shared between jobs & pipelines per-branch per-runner
cache:
  key: $CI_COMMIT_REF_SLUG
  # Preserve cache even if job fails
  when: 'always'
  paths:
    - ./tmp/npm/
    # Homebrew cache is only used by the macos runner
    - ./tmp/Homebrew
    # Chocolatey cache is only used by the windows runner
    - ./tmp/chocolatey/
    # `jest` cache is configured in jest.config.js
    - ./tmp/jest/

stages:
  - build       # Cross-platform library compilation, unit tests

image: registry.gitlab.com/matrixai/engineering/maintenance/gitlab-runner

build:linux:
  stage: build
  needs: []
EOF
cat << EOF
  parallel: $CI_PARALLEL
EOF
cat << "EOF"
  script:
    - >
      nix-shell --arg ci true --run $'
      npm test -- --ci --coverage --shard="$CI_NODE_INDEX/$CI_NODE_TOTAL";
      '
  artifacts:
    when: always
    reports:
      junit:
        - ./tmp/junit/junit.xml
      coverage_report:
        coverage_format: cobertura
        path: ./tmp/coverage/cobertura-coverage.xml
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'

# Disabled pending fixes
.build:windows:
  stage: build
  needs: []
EOF
cat << EOF
  parallel: $CI_PARALLEL
EOF
cat << "EOF"
  tags:
    - windows
  before_script:
    - mkdir -Force "$CI_PROJECT_DIR/tmp"
  script:
    - .\scripts\choco-install.ps1
    - refreshenv
    - npm install --ignore-scripts
    - $env:Path = "$(npm root)\.bin;" + $env:Path
    - npm test -- --ci --coverage --shard="$CI_NODE_INDEX/$CI_NODE_TOTAL"
  artifacts:
    when: always
    reports:
      junit:
        - ./tmp/junit/junit.xml
      coverage_report:
        coverage_format: cobertura
        path: ./tmp/coverage/cobertura-coverage.xml
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'

# Disabled pending fixes
.build:macos:
  stage: build
  needs: []
EOF
cat << EOF
  parallel: $CI_PARALLEL
EOF
cat << "EOF"
  tags:
    - saas-macos-medium-m1
  image: macos-12-xcode-14
  script:
    - eval "$(brew shellenv)"
    - ./scripts/brew-install.sh
    - hash -r
    - npm install --ignore-scripts
    - export PATH="$(npm root)/.bin:$PATH"
    - npm test -- --ci --coverage --shard="$CI_NODE_INDEX/$CI_NODE_TOTAL"
  artifacts:
    when: always
    reports:
      junit:
        - ./tmp/junit/junit.xml
      coverage_report:
        coverage_format: cobertura
        path: ./tmp/coverage/cobertura-coverage.xml
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
EOF