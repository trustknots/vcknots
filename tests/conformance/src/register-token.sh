#!/usr/bin/env bash

set -euo pipefail

TOKEN="${1:-}"

if [[ -z "$TOKEN" ]]; then
  echo "Usage: $0 <token>"
  exit 1
fi

docker compose \
  -f tests/conformance/suites/docker-compose-prebuilt.yml \
  exec -T mongodb \
  mongosh mongodb://localhost/test_suite \
  --eval "
    db.API_TOKEN.updateOne(
      { _id: 'ci_token' },
      {
        \$set: {
          _id: 'ci_token',
          owner: {
            sub: 'ci',
            iss: 'https://localhost.emobix.co.uk:8443'
          },
          info: {},
          token: '$TOKEN',
          expires: null
        }
      },
      { upsert: true }
    )
  "