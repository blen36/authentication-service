FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /build

COPY pom.xml ./
COPY src/main ./src/main
# Tests were run separately in step 7; Testcontainers needs a Docker daemon.
RUN mvn -B -ntp -Dmaven.test.skip=true package

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --no-create-home app

COPY --from=build --chown=app:app /build/target/authentication-service-0.0.1-SNAPSHOT.jar /app/app.jar

USER app
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
