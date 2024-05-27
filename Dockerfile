FROM openjdk:17-jdk

COPY target/spring-security-2-1.0-SNAPSHOT.jar /app/spring-security.jar

WORKDIR /app

EXPOSE 8080

CMD ["java", "-jar" ,"spring-security.jar"]