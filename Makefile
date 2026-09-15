.PHONY: help up down restart logs shell db migrate scan worker-logs ps check-ports

help:
	@echo "make up          check ports, start stack, migrate"
	@echo "make check-ports require HTTP_PORT/MYSQL_PORT in .env and verify they are free"
	@echo "make down        stop"
	@echo "make scan T=x    enqueue + drain stages (CLI)"
	@echo "make logs        all logs"
	@echo "make shell       php shell"
	@echo "make db          mariadb cli"

check-ports:
	@python3 bin/check-ports

up:
	@test -f .env || cp .env.example .env
	@$(MAKE) check-ports
	docker compose up -d --build --remove-orphans

down:
	docker compose down --remove-orphans

restart: down up

logs:
	docker compose logs -f --tail=100

worker-logs:
	docker compose logs -f worker --tail=100

shell:
	docker compose exec php bash

db:
	docker compose exec mariadb mariadb -udns_scan -pdns_scan dns_scan

mysql: db

migrate:
	docker compose exec php ./yii migrate

scan:
	@test -n "$(T)" || (echo "Usage: make scan T=example.com"; exit 1)
	docker compose exec php ./yii scan:run $(T)

ps:
	docker compose ps
