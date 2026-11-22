.PHONY: all build run dev test test-race vet fmt lint playwright-install playwright-check clean help

all: build

## build: Сборка исполняемого бинарного файла tbank-capture
build:
	go build -o tbank-capture ./cmd/tbank-capture

## run: Сборка и запуск приложения (автоматически использует .env при наличии)
run: build
	@if [ ! -f .env ]; then \
		echo "Предупреждение: файл .env не найден. Скопируйте .env.example в .env:"; \
		echo "  cp .env.example .env"; \
	fi
	./tbank-capture

## dev: Прямой запуск через go run без отдельной стадии сборки
dev:
	@if [ ! -f .env ]; then \
		echo "Предупреждение: файл .env не найден. Скопируйте .env.example в .env:"; \
		echo "  cp .env.example .env"; \
	fi
	go run ./cmd/tbank-capture

## test: Запуск всех юнит- и интеграционных тестов
test:
	go test ./...

## test-race: Запуск тестов с проверкой состояния гонки памяти (race detector)
test-race:
	go test -race ./...

## vet: Статический анализ кода go vet
vet:
	go vet ./...

## fmt: Автоматическое форматирование исходного кода gofmt
fmt:
	gofmt -w .

## lint: Проверка форматирования и статический анализ
lint: vet
	test -z "$$(gofmt -l .)"

## playwright-install: Загрузка драйвера Playwright и браузера Chromium
playwright-install:
	./scripts/install-playwright.sh

## playwright-check: Проверка готовности Playwright и Chromium без запуска
playwright-check:
	./scripts/install-playwright.sh --check

## clean: Удаление скомпилированного бинарника
clean:
	rm -f tbank-capture

## help: Справка по доступным командам Makefile
help:
	@echo "Доступные команды Makefile:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':'

