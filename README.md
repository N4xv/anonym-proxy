# AnonymProxy (TLS Fingerprint Mutator)...

Un proxy inverso asíncrono de bajo nivel desarrollado en **Rust** enfocado en la evasión de sistemas anti-bots y firewalls corporativos mediante la **mutación dinámica de huellas criptográficas TLS (JA3/JA4)** en tiempo real.

## Por qué es diferente

Los proxies tradicionales (Nginx, Caddy) mantienen una estructura estática en la negociación TLS, lo que permite a sistemas como Cloudflare o Akamai identificar y bloquear firmas automatizadas.

`AnonymProxy` intercepta el paquete crudo `Client Hello` antes de que llegue al destino, extrae el vector variable de extensiones criptográficas, aplica un barajado dinámico basado en un algoritmo **Fisher-Yates (Xorshift)** y recalcula los bytes de longitud de las cabeceras a nivel de bit. Cada petición saliente tiene una huella dactilar completamente única e impredecible.

## Stack Tecnologico

- **Rust 1.95** (Rendimiento nativo sin Garbage Collector).
- **Tokio Context**: Arquitectura asincrona no bloqueante para concurrencia masiva.
- **Clap**: Interfaz de linea de comandos (CLI) estructurada.
- **Tracing**: Sistema de logs de diagnostico de alta velocidad.

## Guia de Uso

### 1. Compilacion

Para compilar el binario optimizado de produccion:

```bash
cargo build --release
```

### 2. Ejecucion

Levanta el proxy escuchando en un puerto local y redirigiendo el trafico hacia tu servidor de destino (ejemplo: el DNS seguro de Cloudflare):

```bash
./target/release/anonym-proxy --listen 127.0.0.1:8080 --target 1.1.1.1:443
```

### 3. Prueba de concepto

Simula una peticion HTTPS atacando directamente al puerto del proxy para observar la mutacion en directo:

```bash
curl -v -k -H "Host: 1.1.1.1" https://127.0.0.1:8080/
```

## Arquitectura Interna

1. **TCP Listener**: Captura el flujo de bytes asincrono.
2. **Byte Peeking**: Analiza si el primer byte coincide con un Handshake TLS (`0x16`).
3. **Dynamic Pointer Scanning**: Salta los bloques variables de Session ID y Cipher Suites leyendo sus longitudes en memoria.
4. **Payload Mutation**: Desordena las extensiones e inyecta las nuevas longitudes en la cabecera del registro.
