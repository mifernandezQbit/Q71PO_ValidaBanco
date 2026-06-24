#***************************************************************************************#
# Función: extraerErroresV2                                                             #
# Propósito:  Recibe un diccionario con respuesta JDE (estructura desconocida)          #
#  y devuelve una lista de errores normalizados.                                        #
#     Recibe un diccionario con respuesta JDE (estructura desconocida) y devuelve una   #
# lista de errores normalizados.                                                        #
#   La función recorre el JSON de forma recursiva porque la estructura es desconocida.  #
#    Durante el recorrido detecta errores estructurados (errors / error) y los normaliza.#
#   Si encuentra al menos uno, ignora los mensajes de texto (jde__simpleMessage).       #
#   Si no encuentra errores estructurados, intenta parsear el simpleMessage con         #
# expresiones regulares.                                                                #
#   Finalmente, devuelve una lista única de errores en un formato estándar              #
# Entrada:  payload - Diccionario con respuesta de orquestación JDE ejecutada           #
# Salida: lista de errores normalizada con estructura usada desde el portal             #
# VERSION: 1.0.0                                                                        #
#***************************************************************************************#
import re
 
def extraerErroresV2(payload: dict) -> list:
 
    collected_errors = []
    found_structured_errors = False  # Se utiliza para decidir si imprimimos el jde_simpleMessage
 
    # Normaliza strings
    def clean_text(value):
        if not value:
            return ""

        text = str(value)

        # normalizar dobles escapes (\n literal)
        text = text.replace("\\n", " ")

        # Caso unicode escapado
        if "\\u" in text:
            try:
                text = text.encode("utf-8").decode("unicode_escape")
            except:
                pass

        # Caso encoding roto (UTF-8 mal interpretado como latin1)
        if "Ã" in text or "�" in text:
            try:
                text = text.encode("latin1").decode("utf-8")
            except:
                pass

        return (
            text
            .replace("\u000a", " ")
            .replace("\n", " ")
            .strip()
    )

    # Transforma cualquier error de JDE en el formato definido
    def normalize_error(err: dict) -> dict:
        title = clean_text(err.get("TITLE", ""))
 
        # excluir warnings
        if title.upper().startswith("WARNING"):
            return None
 
        return {
            "code": clean_text(err.get("CODE", "")),
            "title": title,
            "desc": clean_text(err.get("DESC", "")),
            "errorControl": clean_text(err.get("ERRORCONTROL", "")),
            "controlTitle": clean_text(err.get("CONTROLTITLE", "")),
            "alias": clean_text(err.get("ALIAS", ""))
        }
 
    # Parsea el jde__simpleMessage al formato definido
    def extract_from_simple_message(message: str) -> list:
        results = []
 
        blocks = re.split(r'\(\d+\)', message)
 
        for block in blocks:
            if not block.strip():
                continue
 
            title_match = re.search(r'Title:\s*(.*?),', block)
            desc_match = re.search(r'Description:\s*(.*?),', block)
            code_match = re.search(r'Code-Control:\s*([A-Z0-9]+)-(\d+)', block)
            alias_match = re.search(r'Alias:\s*([^,]+)', block)
            field_match = re.search(r'Field:\s*([^,]+)', block)
            table_match = re.search(r'Table:\s*([^,]+)', block)
 
            if code_match and title_match and desc_match:
                code, error_control = code_match.groups()
                title = clean_text(title_match.group(1))
                desc = clean_text(desc_match.group(1))
                alias = clean_text(alias_match.group(1)) if alias_match else ""
                field = clean_text(field_match.group(1)) if field_match else ""
                table = clean_text(table_match.group(1)) if table_match else ""
 
                # excluir warnings
                if title.upper().startswith("WARNING"):
                    continue
 
                results.append({
                    "code": clean_text(code),
                    "title": title,
                    "desc": desc,
                    "errorControl": clean_text(error_control),
                    "controlTitle": "",
                    "alias": alias,
                    "field": field,
                    "table": table
                })
 
        return results
 
    # Recorrido recursivo
    def recursive_scan(node):
        nonlocal found_structured_errors

        if isinstance(node, dict):

            # detectar errores sin importar mayúsculas/minúsculas
            errors_list = node.get("errors") or node.get("Errors")
            error_list = node.get("error") or node.get("Error")

            # detectar si hay errores estructurados en cualquier lado
            if isinstance(errors_list, list) and len(errors_list) > 0:
                found_structured_errors = True

            if isinstance(error_list, list) and len(error_list) > 0:
                found_structured_errors = True

            # detectar estructura de error JDE en message
            # algunos servicios devuelven errores dentro de listas dinámicas
            # ejemplo:
            # "message": {
            #   "NombreServicio": [
            #       {
            #           "code": "...",
            #           "description": "...",
            #           "errorLevel": "error"
            #       }
            #   ]
            # }
            for key, value in node.items():

                if isinstance(value, list):

                    for err in value:

                        if isinstance(err, dict):

                            if (
                                "code" in err and
                                "description" in err and
                                (
                                    "errorLevel" in err or
                                    "control" in err
                                )
                            ):

                                found_structured_errors = True

                                normalized = {
                                    "code": clean_text(err.get("code", "")),
                                    "title": clean_text(err.get("description", "")),
                                    "desc": clean_text(err.get("glossary", "")),
                                    "errorControl": clean_text(err.get("control", "")),
                                    "controlTitle": clean_text(key),
                                    "alias": ""
                                }

                                collected_errors.append(normalized)

            # recorrer primero SIEMPRE (búsqueda global)
            for value in node.values():
                recursive_scan(value)

            # ------------------------------------------------------------------
            # FORMATO CLÁSICO "errors"
            # ------------------------------------------------------------------
            if isinstance(errors_list, list):

                for err in errors_list:

                    normalized = normalize_error(err)

                    if normalized:
                        collected_errors.append(normalized)

            # ------------------------------------------------------------------
            # FORMATO CLÁSICO "error"
            # ------------------------------------------------------------------
            if isinstance(error_list, list):

                for err in error_list:

                    normalized = normalize_error(err)

                    if normalized:
                        collected_errors.append(normalized)

            # ------------------------------------------------------------------
            # FALLBACK jde__simpleMessage
            # ------------------------------------------------------------------
            if not found_structured_errors:

                jde_status = clean_text(
                    node.get("jde__status", "")
                ).upper()

                # si es WARN no devolvemos errores
                if jde_status == "WARN":
                    return

                if "jde__simpleMessage" in node:

                    extracted = extract_from_simple_message(
                        node["jde__simpleMessage"]
                    )

                    if extracted:
                        collected_errors.extend(extracted)

                    else:
                        # fallback cuando no hay formato estructurado
                        collected_errors.append({
                            "code": "0000",
                            "title": "Error Desconocido",
                            "desc": clean_text(node["jde__simpleMessage"]),
                            "errorControl": "",
                            "controlTitle": "",
                            "alias": ""
                        })

        elif isinstance(node, list):

            for item in node:
                recursive_scan(item)

    # Eliminación de duplicados
    def deduplicate(errors: list) -> list:
        seen = set()
        unique = []
 
        for err in errors:
            key = (err["code"], err["title"])
            if key not in seen:
                seen.add(key)
                unique.append(err)
 
        return unique
 
    # Ejecución
    recursive_scan(payload)
 
    return deduplicate(collected_errors)