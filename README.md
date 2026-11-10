# Authentication Service

Java 21, Spring Boot, PostgreSQL и RSA. Gateway слушает 8080, User Service — 8081, Auth — 8082.

## Первый запуск двух сервисов

1. Скопируй `.env.example` в `.env` в каждом репозитории. В PowerShell команда выглядит как `Copy-Item .env.example .env`. Если файл уже существует, добавь новые настройки в него.
2. Задай пароли баз данных. Если используешь существующие Docker volumes, укажи их текущие пароли. В обоих сервисах задай один и тот же случайный `AUTH_REGISTRATION_KEY` длиной от 32 символов. Для нового значения можно выполнить `openssl rand -hex 32`.
3. В корне Auth создай новую пару ключей. Команды для Git Bash с OpenSSL приведены ниже. Выполни их один раз перед первым запуском с этой парой. Старые токены после замены ключа и перехода на `user_id` потребуют повторного входа.

```bash
mkdir -p secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/private-key.pem
openssl pkey -in secrets/private-key.pem -pubout -out secrets/public-key.pem
```

4. На Linux процесс в контейнере должен иметь право читать смонтированный файл закрытого ключа. Для Docker Engine без user namespace remapping команда `setfacl -m u:10001:r secrets/private-key.pem` предоставляет доступ пользователю образа. Не добавляй `.env` и `secrets/` в Git.
5. Один раз создай общую сеть командой `docker network create java-advanced-services`. Из корня User запусти `docker compose up -d --build`, затем выполни ту же команду из корня Auth. Сеть связывает контейнеры приложений. У каждого репозитория остаётся своя сеть с базой данных.
6. Открой `http://localhost:8082/.well-known/jwks.json`. В ответе должен быть один открытый RSA-ключ с полями `kid`, `n` и `e`.

Compose монтирует файлы в `/run/secrets/`. При запуске из IntelliJ укажи в Run Configuration переменные из `.env.example`, `USER_SERVICE_URL=http://localhost:8081` и `AUTH_DB_PASSWORD`. Используй локальную БД или `docker compose -f compose.auth-db.yaml up -d`. Опциональный bootstrap создаёт учётные данные администратора для уже выделенного ID пользователя. Включай его только с заполненными `AUTH_BOOTSTRAP_USER_ID`, `AUTH_BOOTSTRAP_LOGIN` и `AUTH_BOOTSTRAP_PASSWORD`.

## Проверка регистрации в PowerShell

```powershell
$account = @{
    name = "Anna"
    surname = "Testova"
    email = "anna.test@example.org"
    birthDate = "2000-05-15"
    login = "anna.test"
    password = "LocalDemoPass123!"
}
Invoke-RestMethod -Method Post -Uri http://localhost:8082/api/auth/register -ContentType application/json -Body ($account | ConvertTo-Json)
$login = @{login=$account.login; password=$account.password} | ConvertTo-Json
$tokens = Invoke-RestMethod -Method Post -Uri http://localhost:8082/api/auth/login -ContentType application/json -Body $login
$headers = @{Authorization="Bearer $($tokens.accessToken)"}
$identity = Invoke-RestMethod http://localhost:8082/api/auth/validate -Headers $headers
Invoke-RestMethod "http://localhost:8081/api/users/$($identity.userId)" -Headers $headers
```

При первом вызове ожидай 201 и роль USER. Для проверки компенсации отправь другой email с занятым логином. Ожидай 409. Затем отправь тот же новый email со свободным логином. Ответ 201 показывает, что временный профиль удалён. В JWT идентификатор называется `user_id`, а в JSON ответа `validate` он по-прежнему называется `userId`.

Клиент передаёт пароль только Auth. Auth передаёт User Service поля профиля и закрытый заголовок `X-Registration-Key`. Отдельный Spring bean `CredentialService` владеет транзакцией записи. Если создание профиля прошло успешно, а сохранение credentials завершилось ошибкой, `RegistrationService` инициирует удаление полученного ID. Если сам DELETE недоступен, Auth возвращает 502 и журналирует ID для сверки. Отказ процесса между двумя вызовами и потеря ответа после создания профиля требуют сверки данных двух сервисов. Гарантированное восстановление после таких сбоев потребовало бы сохранять состояние регистрации.

## Проверка и CI

Включи Docker Desktop и выполни `.\mvnw.cmd clean verify` под Java 21. GitHub Actions запускает сборку и тесты на push, затем SonarQube Cloud и сборку Docker-образа. В репозитории Auth нужны секрет `SONAR_TOKEN` и переменные `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY`. Project key у Auth должен указывать на его собственный проект в SonarQube. Для IntelliJ установи высокий порог wildcard-импортов в Editor → Code Style → Java → Imports, например 999 для обычных и статических импортов.
