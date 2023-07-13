FROM registry.serviceit.su:443/gradle:7.4.2-jdk17 as build-stage
WORKDIR /app
COPY . .
RUN gradle clean bootJar

FROM registry.serviceit.su:443/bellsoft/liberica-openjdk-debian:17.0.3 as project
VOLUME /its/config
COPY --from=build-stage /app/build/libs/*.jar /app.jar
COPY version.properties /
EXPOSE 9090
ENTRYPOINT ["java","-jar","/app.jar","su.serviceit.work_schedule.Application", "--spring.config.location=/its/config/application.properties"]