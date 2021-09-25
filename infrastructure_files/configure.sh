#!/bin/bash

unset $(grep -v '^#' ./setup.env | sed -E 's/(.*)=.*/\1/' | xargs)
export $(grep -v '^#' ./setup.env | xargs)

envsubst < docker-compose.yml.tmpl > docker-compose.yml
envsubst < management.json.tmpl > management.json
