import io
import json
import logging

import requests

from fdk import response
## Nueva función para identificar errores
from utilidades.errores.core import extraerErroresV2

def handler(ctx, data: io.BytesIO = None):
    try:
        cfg = ctx.Config()
        urlOrc = cfg["urlLogin"]
        body = json.loads(data.getvalue())
        params = body

    except (Exception, ValueError) as ex:
        logging.getLogger().info("error parsing json payload: " + str(ex))

    respuesta = sendQuery(params, urlOrc)
    respJson = respuesta.json()
    if respuesta.status_code == 444:
        respJson = {
            "success": False,
            "rowset": None,
            "tokenExpirado": True,
            "data": None,
            "errorJde": True,
            "errorsList": [],
        }
    else:
        respJson = procesarRespuesta(
            respJson
        )

    return response.Response(
        ctx,
        response_data=json.dumps(respJson),
        headers={"Content-Type": "application/json"},
    )


def sendQuery(params, urlOrc):
    url = urlOrc + "/v3/orchestrator/Q71PO_ORCH_ValidaBanco"
    try:
        auth_data = params

        resp = requests.post(url, json=auth_data)
    except Exception as e:
        resp = "Falló: " + str(e)
    return resp


def procesarRespuesta(respuesta):
    resultado = {}
    if "jde__status" in respuesta:
        if (respuesta["jde__status"]).strip() == "SUCCESS" or (
            respuesta["jde__status"].strip() == "WARN"
        ):
            # devuelvo respuesta
            resultado = {
                "success": True,
                "data": None,
                "rowset": respuesta,
                "errorJde": False,
                "tokenExpirado": False,
                "errorsList": None,
            }
        else:
            resultado = {
                "success": True,
                "rowset": None,
                "data": None,
                "errorJde": True,
                "tokenExpirado": False,
                "errorsList": respuesta,
            }
    else:
        resultado = {
            "success": False,
            "rowset": [],
            "data": {},
            "errorJde": True,
            "tokenExpirado": False,
            "errorsList": procesarErrores(respuesta),
        }

    return resultado

'''
def extraerErrores(respuesta):
    errorsList = []

    # Verificar que el JSON es un diccionario y contiene la clave 'message'
    if isinstance(respuesta, dict) and "message" in respuesta:
        infoMessage = respuesta["message"]

        # Verificar que 'infoMessage' es un diccionario
        if isinstance(infoMessage, dict):
            # Recorrer todas las claves de infoMessage
            for key, value in infoMessage.items():
                # Verificar si la clave actual tiene como valor un diccionario y contiene a su vez "JAS Response"
                if isinstance(value, dict) and "JAS Response" in value:
                    jasResponse = value["JAS Response"]

                    # Recorrer todas las claves dentro de 'JAS Response'
                    for keyInJasResponse, valueInJasResponse in jasResponse.items():
                        # Verificar si contiene la clave 'errors' y es un diccionario
                        if (
                            isinstance(valueInJasResponse, dict)
                            and "errors" in valueInJasResponse
                        ):
                            errors = valueInJasResponse["errors"]

                            # Verificar si "errors" es una lista y tiene elementos
                            if isinstance(errors, list) and errors:
                                # Recorrer cada error dentro de la lista
                                for error in errors:
                                    if isinstance(error, dict):
                                        # Crear un diccionario con las claves 'code', 'title' y 'desc'
                                        errorInfo = {
                                            "code": error.get("CODE", "000"),
                                            "title": error.get(
                                                "TITLE", "ERROR INESPERADO"
                                            ),
                                            "desc": error.get(
                                                "DESC", "Descripción no disponible"
                                            ),
                                        }
                                        # Agregar el error a la lista de errores
                                        errorsList.append(errorInfo)
                                
                elif isinstance(value, dict) and "message" in value:
                    errorsList.extend(extraerErrores(value))
        else:
            infoError = {"code": "0000", "title": "Error", "desc": infoMessage}
            # Agregar el diccionario a la lista de errores
            errorsList.append(infoError)
    return errorsList
'''

## Función para revisar los errores que retornó la orquestación y normalizarlos en una lista única
def procesarErrores(respuesta):
    errorsList = extraerErroresV2(respuesta) #extraerErrores(respuesta)
    return errorsList
