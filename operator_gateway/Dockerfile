FROM nginx:1.30-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949
RUN apk add --no-cache iptables=1.8.13-r0 iproute2=7.0.0-r0 util-linux=2.42.3-r1
ENTRYPOINT ["/bin/sh", "/opt/honeypot/runtime_guard.sh"]
CMD ["nginx", "-e", "stderr", "-g", "daemon off;"]
