# prtg_mpp/Dockerfile
FROM paessler/multi-platform-probe:latest
USER root

# Install Python3, pip, sudo, and required Python modules
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sudo \
    && pip3 install --no-cache-dir docker \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure sudoers for user 101 to run scripts as root
RUN echo "paessler_mpprobe ALL=(root) NOPASSWD:SETENV: /usr/bin/python3" > /etc/sudoers.d/prtg && \
    chmod 0440 /etc/sudoers.d/prtg

# Copy Python scripts
COPY --chmod=755 ./docker_stats_writer.py /opt/paessler/share/scripts/docker_stats_writer.py
COPY --chmod=755 ./docker_stats_reader.py /opt/paessler/share/scripts/docker_stats_reader.py
COPY --chmod=755 ./setup_docker_monitoring.py /opt/paessler/share/scripts/setup_docker_monitoring.py

# Copy certs and entrypoint
COPY ./certs /config/certs/
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/run-prtgmpprobe.sh", "service-run"]