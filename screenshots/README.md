# Capturas de pantalla — VTP Attacks

Capturas del laboratorio en orden de demostración.

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | [01_topologia.png](/screenshots/01_topologia.png) | Vista de la topología funcional en PNETLab. Se validan las etiquetas de nombres, matrícula (`20250737`), interfaces físicas conectadas y el direccionamiento base IP. |
| 2 | [02_sniff_vtp_real.png](/screenshots/02_sniff_vtp_real.png) | Salida en consola de Kali Linux operando bajo el modificador `--sniff-only`. Muestra la captura pasiva y extracción exitosa del dominio `ITLA_SEC` y la revisión actual del switch. |
| 3 | [03_vlan_brief_inicial.png](/screenshots/03_vlan_brief_inicial.png) | Resultado del comando `show vlan brief` en `SW1` previo al ataque, reflejando el estado inicial y legítimo de los segmentos de red. |
| 4 | [04_ejecucion_ataque_add.png](/screenshots/04_ejecucion_ataque_add.png) | Ejecución del script en modo inserción (`-a add -v 666`). Se evidencia el cálculo en tiempo real de la estructura binaria y la ráfaga de anuncios inyectados. |
| 5 | [05_vlan_brief_pwned.png](/screenshots/05_vlan_brief_pwned.png) | Verificación en la CLI de Cisco. Captura que demuestra la asimilación forzada del número de revisión `+50` y la creación no autorizada de la VLAN 666 (`PWNED_ZONE`). |
| 6 | [06_ejecucion_ataque_del.png](/screenshots/06_ejecucion_ataque_del.png) | Registro del script ejecutando el borrado destructivo (`-a delete -v 20`), propagando la eliminación de la VLAN crítica de producción de forma inmediata. |
| 7 | [07_mitigacion_vtp.png](/screenshots/07_mitigacion_vtp.png) | Comandos aplicados en la consola del switch aplicando el endurecimiento de la infraestructura mediante la inhabilitación del protocolo VTP. |
