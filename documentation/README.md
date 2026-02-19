# Guía Docente (modo laboratorio) para probar cada riesgo API1–API10

* **Qué probar (request)**
* **Qué debe pasar en `MODE=vuln`**
* **Qué debe pasar en `MODE=fixed`**
* **“Código vulnerable vs parche”** (solo el fragmento relevante por API, para que usted lo muestre en clase sin leer todo el archivo)

> **Setup (1 minuto)**

1. Levante en vuln: `MODE=vuln` → `docker compose up --build`
2. Swagger: `http://localhost:8000/docs`
3. Para fixed: cambie `MODE=fixed` y reconstruya: `docker compose up --build`

---

# API2 primero (para conseguir token)

Antes de probar API1,3,5,9 (que piden auth), haga login.

### Login (token)

**Request**

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"u1@demo.com","password":"cualquiercosa"}'
```

**Esperado**

* `MODE=vuln`: devuelve `access_token` aunque el password sea cualquiera
* `MODE=fixed`: debe fallar si password incorrecto (use el demo password):

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"u1@demo.com","password":"U1-pass-123!"}'
```

Guarde el token en una variable:

```bash
TOKEN="PEGUE_EL_TOKEN"
```

---

# API1 — Broken Object Level Authorization (BOLA)

### Prueba (IDOR/BOLA)

**Request (como u1 intenta ver orden de u2)**

```bash
curl -s http://localhost:8000/api/orders/1002 -H "Authorization: Bearer $TOKEN"
```

**Esperado**

* `vuln`: devuelve el pedido `1002` (de u2) ✅ (vulnerable)
* `fixed`: `403 Forbidden` ✅ (parchado)

### Código vulnerable vs parche (fragmento)

**Vulnerable**

```python
# vuln: devuelve el pedido aunque no sea del usuario
return order
```

**Parche**

```python
if MODE == "fixed":
    # mitigación: validar propiedad del recurso
    if order["user_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(403, "Forbidden")
```

---

# API2 — Broken Authentication (lo del material: brute force, JWT, credenciales URL, re-auth)

## 2.1 Fuerza bruta / bloqueo

**Request (5 intentos fallidos en fixed)**

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"u1@demo.com","password":"MAL_PASSWORD_123"}'
done
```

**Esperado**

* `vuln`: siempre responde 200 (o 200 con token) si el email existe ✅ vulnerable
* `fixed`: después de varios fallos → `429 Too Many Requests` ✅ parche (bloqueo)

## 2.2 Credenciales en URL (anti-patrón)

**Request**

```bash
curl -s "http://localhost:8000/api/auth/login_via_url?email=u1@demo.com&password=loquesea"
```

**Esperado**

* `vuln`: devuelve token + warning ✅ vulnerable
* `fixed`: `410 Disabled in fixed mode` ✅ parche

## 2.3 Re-autenticación para cambio sensible (cambio de correo)

Primero obtenga token válido (en fixed use password correcto).

**Request (cambiar email de u2 estando como u1)**

```bash
curl -s -X POST http://localhost:8000/api/users/u2/change-email \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"new_email":"hacked@demo.com"}'
```

**Esperado**

* `vuln`: cambia el correo de u2 ✅ vulnerable
* `fixed`: `403 Forbidden` (si no es admin) o `401` si no pasa re-auth ✅ parche

**Request fixed correcto (u1 cambiando su propio correo con re-auth)**

```bash
curl -s -X POST http://localhost:8000/api/users/u1/change-email \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"new_email":"u1_new@demo.com","current_password":"U1-pass-123!"}'
```

### Código vulnerable vs parche (fragmentos)

**Vulnerable (login)**

```python
if MODE == "vuln":
    pass_ok = True
```

**Parche (login + bloqueo)**

```python
if MODE == "fixed" and state["blocked_until"] > now():
    raise HTTPException(429, "Temporarily blocked...")

pass_ok = (PASSWORDS.get(email) == password)
```

**Vulnerable (cambio sensible)**

```python
if MODE == "vuln":
    USERS[user_id]["email"] = new_email
```

**Parche (re-auth + ownership)**

```python
if user["id"] != user_id and user["role"] != "admin":
    raise HTTPException(403, "Forbidden")

if PASSWORDS.get(user["email"]) != current_password:
    raise HTTPException(401, "Re-auth failed")
```

---

# API3 — BOPLA (Mass Assignment / propiedad sensible)

### Prueba (escalar rol)

```bash
curl -s -X PUT http://localhost:8000/api/users/u1 \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

**Esperado**

* `vuln`: `role` queda en `admin` ✅ vulnerable
* `fixed`: ignora `role` (solo permite email) ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
target.update(body)  # permite role="admin"
```

**Parche**

```python
allowed = {"email"}  # NO permitir role
for k in list(body.keys()):
    if k not in allowed:
        body.pop(k, None)
```

---

# API4 — Unrestricted Resource Consumption

### Prueba (payload grande)

```bash
curl -s "http://localhost:8000/api/reports/export?size=50000"
```

**Esperado**

* `vuln`: responde, puede demorar/consumir recursos ✅ vulnerable
* `fixed`: `400 Limit exceeded` si size > 5000 ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
data = [{"i": i, "value": "x"*50} for i in range(size)]
```

**Parche**

```python
if MODE == "fixed":
    if size > 5000:
        raise HTTPException(400, "Limit exceeded (demo)")
```

---

# API5 — Broken Function Level Authorization (Admin sin control)

### Prueba (listar usuarios)

```bash
curl -s http://localhost:8000/api/admin/users -H "Authorization: Bearer $TOKEN"
```

**Esperado**

* `vuln`: lista usuarios aunque no sea admin ✅ vulnerable
* `fixed`: `403 Admins only` ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
return {"users": list(USERS.values())}
```

**Parche**

```python
if MODE == "fixed":
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Admins only")
```

---

# API6 — Unrestricted Access to Sensitive Business Flows

### Prueba (automatización simple)

```bash
for i in {1..10}; do
  curl -s -X POST http://localhost:8000/api/checkout \
    -H "Content-Type: application/json" \
    -d '{"product":"limited-item"}' > /dev/null
done
echo "done"
```

**Esperado**

* `vuln`: todo pasa sin fricción ✅ vulnerable
* `fixed`: se siente “más lento” por cooldown (simula control) ✅ parche demo

### Código vulnerable vs parche

**Vulnerable**

```python
return {"status": "purchased", ...}
```

**Parche demo**

```python
if MODE == "fixed":
    time.sleep(0.3)
```

---

# API7 — SSRF

### Prueba (URL arbitraria)

```bash
curl -s "http://localhost:8000/api/fetch?url=https://httpbin.org/get"
```

Luego intente un destino “no permitido”:

```bash
curl -s "http://localhost:8000/api/fetch?url=http://127.0.0.1:8000/health"
```

**Esperado**

* `vuln`: intenta hacer la solicitud (posible acceso interno) ✅ vulnerable
* `fixed`: bloquea por allowlist con `400 URL not allowed` ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
r = requests.get(url, timeout=2)
```

**Parche**

```python
if MODE == "fixed":
    if not (url.startswith("https://example.com/") or url.startswith("https://httpbin.org/")):
        raise HTTPException(400, "URL not allowed (demo allowlist)")
```

---

# API8 — Security Misconfiguration (errores verbosos)

### Prueba

```bash
curl -s -i http://localhost:8000/api/debug/boom
```

**Esperado**

* `vuln`: expone detalle del error ✅ vulnerable
* `fixed`: mensaje genérico ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
return JSONResponse({"error": str(e), "detail": "stacktrace..."}, status_code=500)
```

**Parche**

```python
return JSONResponse({"error": "Internal error"}, status_code=500)
```

---

# API9 — Improper Inventory Management (versiones legacy expuestas)

### Prueba (v1 sin auth)

```bash
curl -s http://localhost:8000/api/v1/legacy-users
```

### Prueba (v2 con auth)

```bash
curl -s http://localhost:8000/api/v2/users -H "Authorization: Bearer $TOKEN"
```

**Esperado**

* `v1`: siempre expone usuarios (vulnerable por inventario/legacy)
* `v2`: requiere token

> Nota: aquí el “parche” real sería **retirar/decomisionar v1** o exigir auth.
> Si quiere, le dejo parche inmediato: en fixed devolver `410 Gone`.

### Código vulnerable vs parche sugerido

**Vulnerable**

```python
@app.get("/api/v1/legacy-users")
def legacy_users():
    return {"legacy": True, "users": list(USERS.values())}
```

**Parche (recomendado para demo)**

```python
@app.get("/api/v1/legacy-users")
def legacy_users():
    if MODE == "fixed":
        raise HTTPException(410, "Legacy API retired")
    return {"legacy": True, "users": list(USERS.values())}
```

---

# API10 — Unsafe Consumption of APIs (terceros)

### Prueba

```bash
curl -s "http://localhost:8000/api/thirdparty/profile?user=test"
```

**Esperado**

* `vuln`: hace request sin timeout y re-expone raw ✅ vulnerable
* `fixed`: usa timeout + limita tamaño y devuelve solo args ✅ parche

### Código vulnerable vs parche

**Vulnerable**

```python
r = requests.get(url)  # sin timeout
return {"proxy": True, "raw": r.text[:3000]}
```

**Parche**

```python
r = requests.get(url, timeout=2)
if len(r.text) > 2000:
    raise HTTPException(400, "Response too large")
return {"safe_proxy": True, "data": r.json().get("args", {})}
```

---

