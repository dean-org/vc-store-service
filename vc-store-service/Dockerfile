FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd -r -u 10001 vault
COPY --from=build /src/target/vc-store-service-*.jar app.jar
USER vault
EXPOSE 8095
ENTRYPOINT ["java","-jar","/app/app.jar"]
