FROM amazoncorretto:17
LABEL maintainer="Prototal Secret Demo App"
VOLUME /tmp
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar","/app.jar"]

