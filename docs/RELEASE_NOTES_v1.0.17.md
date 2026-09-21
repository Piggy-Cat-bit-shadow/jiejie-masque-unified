# jiejie-masque v1.0.17

v1.0.17 is superseded by the lean CONNECT-IP datapath. The application-owned
pipeline diagnostics mode and its configuration are not part of the current
product.

## Boundaries

The current product keeps transport ownership in the maintained quic-go fork
and keeps CUBIC as the production default. No application pipeline telemetry or
legacy diagnostics configuration is supported.

## Maintained dependency pin

```text
quic-go replacement: v0.61.1-0.20260921033957-4587e96afa35
```
