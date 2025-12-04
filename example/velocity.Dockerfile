FROM eclipse-temurin:24-jre-alpine

WORKDIR /velocity

ARG VELOCITY_VERSION=3.4.0-SNAPSHOT
ARG VELOCITY_BUILD=557
RUN wget -O velocity.jar \
    "https://api.papermc.io/v2/projects/velocity/versions/${VELOCITY_VERSION}/builds/${VELOCITY_BUILD}/downloads/velocity-${VELOCITY_VERSION}-${VELOCITY_BUILD}.jar"

ARG VELOCITY_CONFIG
COPY ${VELOCITY_CONFIG} /velocity/velocity.toml

ENTRYPOINT ["java", "-Xms512M", "-Xmx512M", "-jar", "velocity.jar"]
