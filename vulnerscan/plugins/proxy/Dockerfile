FROM mitmproxy/mitmproxy:latest
COPY vulnerscan_addon.py rules.py /addon/
ENV PYTHONPATH=/addon
EXPOSE 8080 8081
CMD ["mitmweb", "--web-host", "0.0.0.0", "-s", "/addon/vulnerscan_addon.py"]
