# ==============================================================================
# TrustVault - Production Multi-Stage Dockerfile for Render Deployment
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Application with Eclipse Temurin Java 21 JDK
# ------------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS builder

WORKDIR /build

# Copy Maven Wrapper and POM first to leverage Docker layer caching
COPY .mvn ./.mvn
COPY mvnw pom.xml ./

# Normalize line endings and ensure Maven Wrapper is executable
RUN sed -i 's/\r$//' ./mvnw && chmod +x ./mvnw

# Copy application source code
COPY src ./src

# Build production artifact with tests enabled
RUN ./mvnw -B clean package

# ------------------------------------------------------------------------------
# Stage 2: Minimal Production Runtime with Eclipse Temurin Java 21 JRE
# ------------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Create a dedicated non-root system group and user for principle of least privilege
RUN groupadd -r trustvault && \
    useradd -r -g trustvault -m -d /home/trustvault -s /usr/sbin/nologin trustvault

# Create default storage directory for private uploads and assign non-root ownership
RUN mkdir -p /app/private-storage/uploads && \
    chown -R trustvault:trustvault /app

# Copy executable Spring Boot fat JAR from the builder stage
COPY --from=builder --chown=trustvault:trustvault /build/target/trustvault-0.0.1-SNAPSHOT.jar /app/app.jar

# Switch to the non-root user
USER trustvault

# Expose default HTTP port (Render dynamically binds and sets PORT at runtime)
EXPOSE 8080

# Configure JVM flags: respect container cgroups memory/CPU limits
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=60.0"

# Launch Spring Boot with signal forwarding (SIGTERM / SIGINT) to ensure graceful shutdown
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
