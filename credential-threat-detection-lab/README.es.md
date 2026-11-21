# Credential Threat Detection Lab

Proyecto de **seguridad defensiva**: detección de fuerza bruta por SSH, password spraying y compromiso de cuentas por phishing con **Wazuh**, en un
laboratorio virtual aislado, más un detector en Python que prueba la misma lógica en CI.

> **Estado: v0.1, diseño y detección como código.** El laboratorio todavía no se ha ejecutado: las reglas están
> escritas pero aún no se validan en Wazuh y no hay resultados medidos. Ver [`docs/test-plan.md`](docs/test-plan.md).

- **Enfoque:** blue team (reglas de detección, análisis de alertas, respuesta automática y hardening). Los ataques
  se simulan solo para generar evidencia con la cual probar las defensas.
- **Qué hace:** simula dos ataques a credenciales en una red cerrada, los detecta con tres reglas de Wazuh
  mapeadas a MITRE ATT&CK, responde bloqueando la IP y compara una ronda sin controles con otra con controles.
- **Idea clave:** el SIEM no ve el correo de phishing, sino su consecuencia: un inicio de sesión válido desde un
  origen no autorizado.
- **Probar el detector:** `cd detector && python -m pytest -q`
- **Ética:** red interna aislada, cuentas y datos ficticios. El repositorio publica material defensivo; no incluye
  herramientas de ataque, diccionarios ni plantillas de phishing.

Proyecto de la materia Seguridad Informática, Universidad de Guayaquil, Carrera de Software.
Equipo: Vásquez Cubero Arturo José, Delgado Aguilar Jorge, Espinosa Feijoo Anderson Antanas, León Paucar Dean Jaher,
Mendoza Navarrete Gabriel Alejandro.
