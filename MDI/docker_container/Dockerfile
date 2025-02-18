# Create squid proxy container
# Use the official ubuntu/squid image as the base image
FROM ubuntu/squid:latest

# Set non-interactive mode for apt-get to avoid any prompts
ARG DEBIAN_FRONTEND=noninteractive

# Update and install apache2-utils for htpasswd support
RUN apt-get update && \
    apt-get install -y apache2-utils && \
    apt-get clean

# Copy your custom squid.conf to the appropriate directory in the container
COPY config/squid.conf /etc/squid/squid.conf

# Copy your htpasswd passwords file to the appropriate directory
COPY config/htpasswd /etc/squid/passwords

# Expose Squid's default port
EXPOSE 3128

# Start Squid when the container runs
CMD ["squid", "-N"]
