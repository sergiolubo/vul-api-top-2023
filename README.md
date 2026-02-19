# 🔐 Vuln API – OWASP API Top 10 2023 (Educational Demo)

> ⚠️ **Proyecto educativo intencionalmente vulnerable. NO usar en producción.**
> Diseñado para fines académicos en el curso de Desarrollo Seguro de Software.

---

## 📌 Descripción

Este proyecto implementa una API REST desarrollada en **FastAPI** que contiene ejemplos intencionalmente vulnerables alineados con el **OWASP API Security Top 10 – 2023**.

La aplicación permite demostrar:

* Cómo se explota una vulnerabilidad en un entorno controlado
* Qué impacto tiene sobre la confidencialidad, integridad y disponibilidad
* Cómo aplicar una mitigación básica (modo `fixed`)
* Diferencias entre práctica insegura y práctica segura

El proyecto soporta dos modos de ejecución:

* `MODE=vuln` → Comportamiento vulnerable
* `MODE=fixed` → Mitigaciones básicas aplicadas

---

## 🎯 Objetivos Académicos

Este laboratorio permite:

* Comprender vulnerabilidades comunes en APIs modernas
* Relacionar práctica de desarrollo con estándar OWASP
* Analizar riesgo técnico y de negocio
* Aplicar refactorización básica para mitigar vulnerabilidades
* Contrastar implementación insegura vs segura

---

## 🛠 Tecnologías

* Python 3.11
* FastAPI
* PyJWT
* Requests
* Docker / Docker Compose

---

## 🚀 Instalación y Ejecución

### 1️⃣ Clonar repositorio

```bash
git clone https://github.com/usuario/vuln-api-top10.git
cd vuln-api-top10
```

### 2️⃣ Ejecutar en modo vulnerable (default)

```bash
docker compose up -d --build
```

### 3️⃣ Detener aplicación

```bash
docker compose down
```

---

## 🌐 Acceso

API Base:

```
http://localhost:8000
```

Swagger UI:

```
http://localhost:8000/docs
```

Health Check:

```
http://localhost:8000/health
```

---

## ⚙️ Modos de Ejecución

El comportamiento depende de la variable de entorno `MODE`.

### 🔴 Vulnerable (default)

```yaml
MODE=vuln
```

* No valida ownership en recursos (BOLA)
* Login sin validación real de contraseña
* Sin rate limiting
* Sin validación de expiración JWT
* Mass assignment permitido
* Endpoint admin sin control
* SSRF sin restricciones
* Errores verbosos
* API legacy activa
* Consumo inseguro de terceros

---

### 🟢 Fixed (mitigación básica)

```yaml
MODE=fixed
```

Incluye mitigaciones educativas como:

* Validación de propiedad del recurso
* Verificación real de contraseña
* Bloqueo temporal por intentos fallidos
* Validación de expiración JWT
* Allowlist de propiedades
* Control de rol para funciones administrativas
* Allowlist en SSRF
* Manejo seguro de errores
* Límite básico de recursos
* Timeout y validación en consumo de terceros

> ⚠️ Estas mitigaciones son educativas y no representan implementación productiva completa.

---

## 🧨 Vulnerabilidades Implementadas

| API   | Riesgo OWASP 2023                                  | Endpoint Demo             |
| ----- | -------------------------------------------------- | ------------------------- |
| API1  | Broken Object Level Authorization (BOLA)           | `/api/orders/{id}`        |
| API2  | Broken Authentication                              | `/api/auth/login`         |
| API3  | Broken Object Property Level Authorization (BOPLA) | `/api/users/{id}`         |
| API4  | Unrestricted Resource Consumption                  | `/api/reports/export`     |
| API5  | Broken Function Level Authorization                | `/api/admin/users`        |
| API6  | Unrestricted Access to Sensitive Business Flows    | `/api/checkout`           |
| API7  | Server-Side Request Forgery (SSRF)                 | `/api/fetch`              |
| API8  | Security Misconfiguration                          | `/api/debug/boom`         |
| API9  | Improper Inventory Management                      | `/api/v1/legacy-users`    |
| API10 | Unsafe Consumption of APIs                         | `/api/thirdparty/profile` |

---

## 🧪 Flujo Sugerido de Laboratorio

1. Ejecutar en modo `vuln`
2. Explorar endpoints desde Swagger
3. Identificar comportamiento inseguro
4. Cambiar a `MODE=fixed`
5. Comparar resultados
6. Analizar qué se corrigió y qué falta por mejorar

---

## 🔑 Credenciales de Prueba (Modo Fixed)

| Usuario | Email                                   | Password        |
| ------- | --------------------------------------- | --------------- |
| User 1  | [u1@demo.com](mailto:u1@demo.com)       | U1-pass-123!    |
| User 2  | [u2@demo.com](mailto:u2@demo.com)       | U2-pass-123!    |
| Admin   | [admin@demo.com](mailto:admin@demo.com) | Admin-pass-123! |

---

## 📚 Referencia

OWASP Foundation. (2023).
**OWASP API Security Top 10 – 2023**
[https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)

---

## ⚠️ Advertencia de Seguridad

Este proyecto:

* Contiene vulnerabilidades intencionales
* No debe exponerse a Internet
* No debe usarse como base para producción
* Es exclusivamente para laboratorio y formación académica

---

## 👨‍🏫 Contexto Académico

Desarrollado como recurso de apoyo para cursos de:

* Desarrollo Seguro de Software
* Ingeniería Web
* Seguridad en APIs
* Hacking Ético
* Análisis de Vulnerabilidades

---

## 🧠 Próximas Mejoras (Opcional)

* Integración con base de datos real
* Implementación de rate limiting real
* Logging estructurado
* Tests automatizados
* CI/CD seguro
* Análisis con herramientas SAST/DAST

---

## 📄 Licencia

Uso educativo.
Libre para modificación con fines académicos.

---
