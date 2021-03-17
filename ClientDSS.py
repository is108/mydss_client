import re
import requests
import json
import logging
import base64
import time

from datetime import datetime as dt
from datetime import timedelta
from urllib3 import disable_warnings, exceptions

from JsonGenerator import JsonGenerator
from XMLParser import XMLParser

disable_warnings(exceptions.InsecureRequestWarning)


def base64decode(encode_data):
    return base64.b64decode(encode_data)

def base64encode(decode_data):
    bytes_string = decode_data.encode('ascii')
    return base64.b64encode(bytes_string)

def translit(p_str):
    dictEquivalentSymbols= {
                            "А": "A",
                            "Б": "B",
                            "В": "V",
                            "Г": "G",
                            "Д": "D",
                            "Е": "E",
                            "Ё": "Yo",
                            "Ж": "Zh",
                            "З": "Z",
                            "И": "I",
                            "Й": "Y",
                            "К": "K",
                            "Л": "L",
                            "М": "M",
                            "Н": "N",
                            "О": "O",
                            "П": "P",
                            "Р": "R",
                            "С": "S",
                            "Т": "T",
                            "У": "U",
                            "Ф": "F",
                            "Х": "H",
                            "Ц": "Ts",
                            "Ч": "Ch",
                            "Ш": "Sh",
                            "Щ": "Sch",
                            "Ы": "Y",
                            "Ъ": "",
                            "Ь": "",
                            "Э": "E",
                            "Ю": "Yu",
                            "Я": "Ya",
                            "а": "a",
                            "б": "b",
                            "в": "v",
                            "г": "g",
                            "д": "d",
                            "е": "e",
                            "ё": "yo",
                            "ж": "zh",
                            "з": "z",
                            "и": "i",
                            "й": "y",
                            "к": "k",
                            "л": "l",
                            "м": "m",
                            "н": "n",
                            "о": "o",
                            "п": "p",
                            "р": "r",
                            "с": "s",
                            "т": "t",
                            "у": "u",
                            "ф": "f",
                            "х": "h",
                            "ц": "ts",
                            "ч": "ch",
                            "ш": "sh",
                            "щ": "sch",
                            "ы": "y",
                            "ъ": "",
                            "ь": "",
                            "э": "e",
                            "ю": "yu",
                            "я": "ya",
                            "№": "#",
                            }

    trantab = p_str.maketrans(dictEquivalentSymbols)
    p_str.translate(trantab)
    p_str = re.sub(r'[^a-zA-Z0-9_\-\.\,]', '_', p_str)

    return p_str


class Logger:
    def __init__(self, filename = 'mydss.log'):
        logging.basicConfig(filename=filename, level=logging.INFO)


    def log(self, msg):
        logging.info(msg)

class ClientDSS:

    def __init__(self):
        self.g_dss_url = 'https://dss.uc.rncb.ru:443'
        self.g_resourse = 'urn:cryptopro:dss:signserver:signserver'
        self.g_oauth_clientid = 'Test01'
        self.g_oauth_redirect_uri = 'urn:ietf:wg:oauth:2.0:oob:auto'
        self.g_debug = False
        self.g_username = ''
        self.g_password = ''
        self.g_auth_token = ''
        self.g_refresh_token = ''
        self.g_auth_refid = ''
        self.g_auth_refid_expires_at = ''
        self.g_auth_token_expires_at = ''

        self.logger = Logger()
        self.json_generator = JsonGenerator()
        self.xml_parser = XMLParser()

    def debug_on(self):
        self.g_debug = True

    def debug_off(self):
        self.g_debug = False

    def debug(self, p_text):
        if self.g_debug:
            print((dt.now()-timedelta(seconds = 1)).strftime('%Y-%m-%d %H:%M:%S') + " " + str(p_text))


    # Сеттеры
    def set_username(self, p_username):
        self.g_username = p_username

    def set_password(self, p_password):
        self.g_password = p_password

    def set_auth(self, p_username, p_password):
        self.set_username(p_username)
        self.set_password(p_password)

    def set_resource(self, p_resource):
        self.g_resourse = p_resource

    def set_dss_url(self, p_url):
        self.g_dss_url = p_url

    def set_auth_token(self, p_token):
        self.g_auth_token = p_token

    def set_refresh_token(self, p_token):
        self.g_refresh_token = p_token

    def set_auth_refid(self, p_refid):
        self.g_auth_refid = p_token

    def set_auth_refid_expires(self, expiresin):
        self.g_auth_refid_expires_at = (dt.now()+timedelta(seconds = int(expiresin) - 1)).strftime('%Y-%m-%d %H:%M:%S')

    def set_auth_token_expires(self, expiresin):
        self.g_auth_token_expires_at = (dt.now()+timedelta(seconds = int(expiresin) - 1)).strftime('%Y-%m-%d %H:%M:%S')

    def set_oauth_clientid(self, p_oauth_clientid):
        self.g_oauth_clientid = p_oauth_clientid

    def set_oauth_redirect_uri(self, p_oauth_redirect_uri):
        self.g_oauth_redirect_uri = p_oauth_redirect_uri

    # Геттеры
    def get_username(self):
        return self.g_username

    def get_password(self):
        return self.g_password

    def get_resource(self):
        return self.g_resourse

    def get_dss_url(self):
        return self.g_dss_url

    def get_full_url(self, url):
        return self.g_dss_url + str(url)

    def get_auth_token(self):
        return self.g_auth_token

    def get_refresh_token(self):
        return self.g_refresh_token

    def get_auth_refid(self):
        return self.g_auth_refid

    def get_auth_refid_expires(self):
        return self.g_auth_refid_expires_at

    def get_auth_token_expires(self):
        return self.g_auth_token_expires_at

    def get_oauth_clientid(self):
        return self.g_oauth_clientid

    def get_oauth_redirect_uri(self):
        return self.g_oauth_redirect_uri



    def check_auth(self):
        if self.get_username() == '' or self.get_password == '':
            self.debug('Username or/and password not set. Use set_auth()')
            return False
        else:
            return True

    def does_action_need_confirmation(self, action_response_xml):
        if self.xml_parser.is_final(action_response_xml) == True:
            return False

        return self.xml_parser.refid_exist_in_response(action_response_xml)

    def set_auth_variables(self, response_xml):
        self.set_auth_token(self.xml_parser.get_token_from_response(response_xml))
        self.set_auth_token_expires(self.xml_parser.get_token_expires_from_response(response_xml))

    def set_oauth_variables(self, response_xml):
        self.set_auth_token(self.xml_parser.get_otoken_from_response(response_xml))
        self.set_auth_token_expires(self.xml_parser.get_otoken_expires_from_response(response_xml))
        self.set_refresh_token(self.xml_parser.get_orefresh_token_from_response(response_xml))

    def set_auth_variables_2_confirm(self, response_xml):
        self.set_auth_refid(self.xml_parser.get_refid_from_response(response_xml))
        self.set_auth_refid_expires(self.xml_parser.get_refid_expires_from_response(response_xml))

    def process_error(self, r):
        response = {"status_code": r.status_code, "is_error": 1, "error_description": 'ERROR. Error code - ' + str(r.status_code)}
        return self.json_generator.json2xml(response)

    def process_ok(self, r):
        data = r.content

        if isinstance(data, bytes):
            data = json.loads(data.decode('UTF-8'))

        if isinstance(data, dict):
            return self.json_generator.json2xml(data)

        return data


    def process_response(self, r):
        self.debug('Response: ' + str(r.content))

        if r.status_code == 200:
            return self.process_ok(r)
        else:
            return self.process_error(r)


    #Запрос на проверку, подтверждена ли авторизация
    def check_if_action_confirmed(self, action_refid, code = None, auth_mode = 0):
        self.debug('Checking if action confirmed by client. start')
        self.debug('AUTH_MODE: ' + str(auth_mode))
        self.debug('RefID: ' + str(action_refid))
        self.debug('CODE: ' + str(code))

        url = self.get_full_url('/STS/confirmation')
        body = self.json_generator.json_action_is_confirmed(self.g_resourse, action_refid, code)

        if auth_mode == 1:
            auth = (self.get_username(), self.get_password())
            headers = {'Accept': 'application/json'}

            try:
                r = requests.post(url, headers=headers, auth=auth, json=body, verify=False)
            except Exception as ex:
                self.debug(ex.message)

        else:
            headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}

            try:
                r = requests.post(url, headers=headers, auth=auth, json=body, verify=False)
            except Exception as ex:
                self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))

        if self.xml_parser.is_final(response) == True:
            self.debug('Check result: ACTION was confirmed')

            if auth_mode == 1:
                self.set_auth_variables(response)
                self.debug('AUTH_TOKEN: ' + str(self.get_auth_token()))
        else:
            self.debug('Check result: ACTION still NOT confirmed')

        self.debug('Checking if action confirmed by client. End.')

        return response



    def check_action_confirmed(self, action_refid, code = None):
        return self.check_if_action_confirmed(action_refid, code, 0)

    def check_auth_confirmed(self, action_refid, code = None):
        return self.check_if_action_confirmed(action_refid, code, 1)

    def is_action_confirmed(self, xml):
        result = self.xml_parser.is_final(xml)
        self.debug('Action is confirmed result = ' + result)

        return result


    # Запрос на получение токена авторизации
    def request_auth_token(self):
        self.debug('REQUEST_AUTH_TOKEN')

        url = self.get_full_url('/STS/confirmation')
        auth = (self.get_username(), self.get_password())
        headers = {'Accept': 'application/json'}
        body = self.json_generator.json_request_auth_token(self.get_resource());

        try:
            r = requests.post(url, headers=headers, auth=auth, json=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))

        if r.status_code != 200:
            return response

        if self.does_action_need_confirmation(response) == False:
            self.debug('AUTH DOES NOT NEED CONFIRMATION')
            self.set_auth_variables(response)
            self.debug('AUTH TOKEN: ' + str(self.get_auth_token()))
        else:
            self.debug('AUTH NEED CONFIRMATION')
            self.set_auth_variables_2_confirm(response)
            self.debug('AUTH REFID: ' + str(self.get_auth_refid()))

        return response


    #Получить список всех доступных сертефикатов
    def get_certificates(self):
        self.debug('Get certificates.')

        url = self.get_full_url('/SignServer/rest/api/certificates')
        try:
            headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}

            try:
                r = requests.get(url, headers=headers, verify=False)
            except Exception as ex:
                self.debug(ex.message)
        except TypeError:
            self.debug("ERROR. AUTH_TOKEN not initialize")
            return

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))

        return response

    #Cоздание запроса на подписание
    def create_sign_transaction(self, sig_type, cert_id, doc_name, doc_type, doc_in_base64):
        self.debug('Create sign transaction start')

        url = self.get_full_url('/SignServer/rest/api/transactions')
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}
        body = self.json_generator.json_create_sign_transaction(sig_type, cert_id, translit(doc_name), doc_type, doc_in_base64)

        self.debug('Create sign transaction request: ' + str(body))
        self.debug('Create sign transaction auth_token: ' + str(self.get_auth_token()))

        try:
            r = requests.post(url, headers=headers, json=body, verify=False);
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Create sign transaction end')

        return response


    def create_cosign_transaction(self, sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc_in_base64):
        self.debug('Create sign transaction start')
        self.logger.log(str("URL: " + str(url)))

        url = self.get_full_url('/SignServer/rest/api/transactions')
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}
        body = self.json_generator.json_create_cosign_transaction(sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc_in_base64)

        self.debug('Create cosign transaction request: ' + str(req_data))
        self.debug('Create cosign transaction auth_token: ' + str(self.get_auth_token()))

        try:
            r = requests.post(url, headers=headers, json=body, verify=False);
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Create cosign transaction end')

        return response

    #Запрос на подтверждение транзакции
    def confirm_sign_transaction(self, transaction_id):

        self.debug('Confirm sign transaction start')

        url = self.get_full_url('/STS/confirmation')
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}
        body = self.json_generator.json_confirm_transaction(self.g_resourse, transaction_id)

        try:
            r = requests.post(url, headers=headers, json=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Confirm sign transaction end')

        return response


    def get_signature2(self, token, pin = None):
        self.debug('Get signature start')

        if pin is None:
            self.debug('Getting signature without pin')
        else:
            self.debug('Getting signature with pin')

        self.debug('Signature token: ' + str(token))

        url = self.get_full_url('/SignServer/rest/api/documents')
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}
        body = self.json_generator.json_get_signature(pin)
        print('BODY - ' +str(body))
        print('HEADERS - ' +str(headers))
        print('URL - ' +str(url))

        try:
            r = requests.post(url, headers=headers, json=body, verify=False)
            print('CONTENT - ' + str(r.content))
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Get signature end')

        if r.status_code != 200:
            return None

        return response


    def get_signature(self, sign_confirmation_xml, pin = None):
        self.debug('Get signature (xml in) start')
        self.debug('Signature token(xml in):')
        self.debug(self.xml_parser.get_token_from_response(sign_confirmation_xml))
        print('TEMP RES' + self.xml_parser.get_token_from_response(sign_confirmation_xml))

        return self.get_signature2(self.xml_parser.get_token_from_response(sign_confirmation_xml), pin)


    def get_signature_xml2(self, token, pin = None):
        self.debug('Get signature start')

        if pin is None:
            self.debug('Getting signature without pin')
        else:
            self.debug('Getting signature with pin')

        self.debug('Signature token: ' + str(token))

        url = self.get_full_url('/SignServer/rest/api/documents')
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.get_auth_token()}
        body = self.json_generator.json_get_signature(pin)

        try:
            r = requests.post(url, headers=headers, json=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Get signature end')

        return response


    def get_signature_xml(self, sign_confirmation_xml, pin = None):
        self.debug('Get signature (xml in) start')
        self.debug('Signature token(xml in):')
        self.debug(self.xml_parser.get_token_from_response(sign_confirmation_xml))

        return self.get_signature_xml2(self.xml_parser.get_token_from_response(sign_confirmation_xml), pin)


    def sign_document(self, sig_type, cert_id, doc_name, doc_type, doc_in_base64):
        self.debug('Document sign start')
        sign_tr_data = self.xml_parser.create_sign_transaction(sig_type, cert_id, doc_name, doc_type, doc_in_base64)

        transaction_id = self.xml_parser.get_tr_id_from_response(sign_tr_data)

        if transaction_id:
            self.debug('Transaction id: ' + str(transaction_id))
            sign_tr_data1 = self.confirm_sign_transaction(transaction_id)
            self.debug('Document sign end')

            return sign_tr_data1

        return sign_tr_data


    def get_sign_document(self, sig_type, cert_id, doc_name, doc_type, doc):
        self.debug('Document sign start')

        return self.sign_document(sig_type, cert_id, doc_name, doc_type, )


    def cosign_document(self, sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc_in_base64):
        self.debug('Document cosign start')
        cosign_tr_data = self.xml_parser.create_sign_transaction(sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc_in_base64)

        transaction_id = self.xml_parser.get_tr_id_from_response(sign_tr_data)

        if transaction_id:
            self.debug('Transaction id: ' + str(transaction_id))
            sign_tr_data1 = self.confirm_sign_transaction(transaction_id)
            self.debug('Document cosign end')

            return sign_tr_data1

        return sign_tr_data


    def get_cosign_document(self, sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc):
        self.debug('Document cosign start')

        return self.cosign_document(sig_type, cert_id, doc_name, doc_type, sign_in_base64)



    def process_oauth_code_response(self, r):
        self.debug('Response: ' + str(r.status_code))
        self.logger.log('POCR Response status: ' + str(r.status_code))

        if r.status_code != 302:
            return None

        try:
            location_header = r.headers['Location']
        except KeyError:
            return None

        self.logger.log('POCR LOCATION: ' + str(location_header))
        self.debug('L=' + str(location_header))

        l_code = re.findall(r'code=([0-9a-zA-Z]*)', location_header)[0]

        return l_code



    def request_oauth_code(self):
        self.debug('REQUEST_OAUTH_CODE')

        url = self.get_full_url('/STS/oauth/authorize')
        body = {'client_id': self.g_oauth_clientid, 'redirect_uri': self.g_oauth_redirect_uri, 'resource': self.get_resource(), 'response_type': 'code', 'scope': 'dss+offline_access'}
        headers = {'Authorization': 'Bearer ' + self.get_auth_token()}

        try:
            r = requests.get(url, headers=headers, params=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        self.logger.log('OAUTH_CODE_URL: ' + url)

        response = self.process_oauth_code_response(r)

        return response



    def request_oauth_token(self):
        self.debug('REQUEST_OAUTH_TOKEN')

        oauth_code = self.request_oauth_code()
        self.logger.log('OAUTH_CODE: ' + str(oauth_code))

        url = self.get_full_url('STS/oauth/token')
        headers = {'Accept': 'application/x-www-form-urlencoded'}
        body = {'client_id': self.g_oauth_clientid, 'redirect_uri': self.g_oauth_redirect_uri, 'code': oauth_code, 'grant_type': 'authorization_code'}

        try:
            r = requests.get(url, headers=headers, params=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))

        if r.status_code != 200:
            return response

        self.set_oauth_variables(response)

        self.debug('OAUTH TOKEN: ' + str(self.get_auth_token()))

        return response



    def refresh_oauth_token(self, p_refresh_token):
        self.debug('REQUEST_AUTH_TOKEN')

        url = self.get_full_url('STS/oauth/token')
        headers = {'Accept': 'application/x-www-form-urlencoded'}
        body = {'client_id': self.g_oauth_clientid, 'refresh_token': self.p_refresh_token, 'grant_type': 'refresh_token'}

        try:
            r = requests.get(url, headers=headers, params=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('REFRESH_OAUTH_TOKEN request: ' + str(r.content))
        self.debug('RESPONSE: ' + str(response))
        self.logger.log('REFRESH_OAUTH_TOKEN response: ' + str(response))

        if r.status_code != 200:
            return response

        self.set_oauth_variables(response)

        return response



    def save_oauth_token(self, p_void = None, p_user_id = None, p_term = None):
        pass

    def refresh_last_osess_if_possible(self, p_void, p_user_id, p_term):
        pass

    def get_hash(self, p_blob):
        pass


    def verify(self, doc_in_base64, sign_in_base64, sig_type = 5):
        self.debug('Verify signature start')

        url = self.get_full_url('/SVS/rest/api/signatures/signersinfo')
        headers = {'Accept': 'application/json'}
        body = self.json_generator.json_get_signature_verify(doc_in_base64, sign_in_base64, sig_type)

        try:
            r = requests.post(url, headers=headers, json=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('Verify signature end')

        return response


    def get_signers_info(self, sign_in_base64, sig_type = 5):
        self.debug('SignersInfo start')

        url = self.get_full_url('/SVS/rest/api/signatures/signersinfo')
        headers = {'Accept': 'application/json'}
        body = self.json_generator.json_get_signers_info(sign_in_base64, sig_type)

        try:
            r = requests.post(url, headers=headers, json=body, verify=False)
        except Exception as ex:
            self.debug(ex.message)

        response = self.process_response(r)
        self.debug('RESPONSE: ' + str(response))
        self.debug('SignersInfo end')

        return response


client = ClientDSS()

#client.debug_on()
client.set_username('name')
client.set_password('password')
res1 = client.request_auth_token()
res2 = client.check_if_action_confirmed(client.xml_parser.get_refid_from_response(res1), None, 1)

time.sleep(15)
res2 = client.check_if_action_confirmed(client.xml_parser.get_refid_from_response(res1), None, 1)
client.set_auth_token(client.xml_parser.get_token_from_response(res2))
res3 = client.get_certificates()
file = open('path_to_file', 'rb')
file_read = file.read()
print('FILE READ ' + str(file_read))
file_64_encode_b = base64.b64encode(file_read)
file_64_encode_s = base64.b64encode(file_read).decode('utf-8')

res4 = client.create_sign_transaction(1, 1320, "file_name", "format", file_64_encode_s)
res5 = client.confirm_sign_transaction(res4)
time.sleep(10)
res6 = client.xml_parser.get_refid_from_response(res5)
res7 = client.check_if_action_confirmed(res6, None, 1)
res8 = client.get_signature(res7, 'password')

print('res1 - ' + str(res1))
print('res2 - ' + str(res2))
print('res3 - ' + str(res3))
print('res4 - ' + str(res4))
print('res5 - ' + str(res5))
print('res6 - ' + str(res6))
print('res7 - ' + str(res7))
print('res8 - ' + str(res8))
