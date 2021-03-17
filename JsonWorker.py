import json
from dicttoxml import dicttoxml


class JsonGenerator:
        def json_request_auth_token(self, g_resourse):
            return {"Resource": "{g_resourse}".format(g_resourse = g_resourse)}



        def json_create_sign_transaction(self, sig_type, cert_id, doc_name, doc_type, doc_in_base64):
            data = {}

            if sig_type == 3:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "'{cert_id}'".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "'{doc_name}'".format(doc_name = doc_name)},
                                {"Name": "DocumentType", "Value": "PDF"},
                                {"Name": "SignatureType", "Value": "PDF"},
                                {"Name": "PDFFormat", "Value": "CMS"}
                                ],
                        "Document": "'{doc_in_base64}'".format(doc_in_base64 = doc_in_base64)
                        }
            elif sig_type == 4:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "{cert_id}".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "{doc_name}".format(doc_name = doc_name)},
                                {"Name": "DocumentType", "Value": "{doc_type}".format(doc_type = doc_type)},
                                {"Name": "SignatureType", "Value": "MSOffice"}
                                ],
                        "Document": "{doc_in_base64} PI base64".format(doc_in_base64 = doc_in_base64)
                        }
            else:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "{cert_id}".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "{doc_name}".format(doc_name = doc_name)},
                                {"Name": "DocumentType", "Value": "{doc_type}".format(doc_type = doc_type)},
                                {"Name": "SignatureType", "Value": "CMS"},
                                {"Name": "CADESType", "Value": "BES"},
                                {"Name": "IsDetached", "Value": "true"}
                                ],
                        "Document": "{doc_in_base64} PI base64".format(doc_in_base64 = doc_in_base64)
                            }


            return data



        def json_create_cosign_transaction(self, sig_type, cert_id, doc_name, doc_type, sign_in_base64, doc_in_base64):
            data = {}

            if sig_type == 3:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "'{cert_id}'".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "'{doc_name}'".format(doc_name = translit(doc_name))},
                                {"Name": "DocumentType", "Value": "'{doc_type}'".format(doc_type = doc_type)},
                                {"Name": "SignatureType", "Value": "PDF"},
                                {"Name": "PDFFormat", "Value": "CMS"}
                                ],
                        "Document": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                        }
            elif sig_type == 4:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "'{cert_id}'".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "'{doc_name}'".format(doc_name = translit(doc_name))},
                                {"Name": "DocumentType", "Value": "'{doc_type}.sig'".format(doc_type = doc_type)},
                                {"Name": "CmsSignatureType", "Value": "cosign"},
                                {"Name": "SignatureType", "Value": "MSOffice"},
                                {"Name": "OriginalDocument", "Value": "'{doc_in_base64}'".format(doc_in_base64 = doc_in_base64)}
                                ],
                        "Document": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                        }
            else:
                data = {
                        "OperationCode": 2,
                        "Parameters":
                                [
                                {"Name": "CertificateID", "Value": "'{cert_id}'".format(cert_id = cert_id)},
                                {"Name": "DocumentInfo", "Value": "'{doc_name}.sig'".format(doc_name = translit(doc_name))},
                                {"Name": "DocumentType", "Value": "'{doc_type}.sig'".format(doc_type = doc_type)},
                                {"Name": "SignatureType", "Value": "CMS"},
                                {"Name": "CADESType", "Value": "BES"},
                                {"Name": "IsDetached", "Value": "true"},
                                {"Name": "CmsSignatureType", "Value": "cosign"},
                                {"Name": "OriginalDocument", "Value": "'{doc_in_base64}'".format(doc_in_base64 = doc_in_base64)}
                                ],
                        "Document": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                        }

            return data



        def json_confirm_transaction(self, g_resourse, transaction_id):
            data = {
                    "Resource": "{g_resourse}".format(g_resourse = g_resourse),
                    "TransactionTokenId": "{transaction_id}".format(transaction_id = transaction_id)
                   }

            return data



        def json_action_is_confirmed(self, g_resourse, ref_id, code = None):
            if code is None:
                return {
                        "Resource": "{g_resourse}".format(g_resourse = g_resourse),
                        "ChallengeResponse": {
                                              "TextChallengeResponse": [{"RefId": "{ref_id}".format(ref_id = ref_id)}]
                                             }
                       }

            else:
                return {
                    "Resource": "{g_resourse}".format(g_resourse = g_resourse),
                    "ChallengeResponse": {
                                          "TextChallengeResponse": [{"RefId": "{ref_id}".format(ref_id = ref_id), "Value": "{code}".format(code = code)}]
                                         }
                   }



        def json_get_signature(self, pin = None):
            data = {}
            if pin is not None:
                data = {"Signature": {"PinCode": "{pin}".format(pin = pin)}}

            return data



        def json_get_signature_verify(self, doc_in_base64, sign_in_base64, sign_type):
            data = {}
            if sign_type == 3 or sign_type == 4:
                data = {
                        "SignatureType": "'{sign_type}'".format(sign_type = sign_type),
                        "VerifyParams": {"VerifyAll": 1},
                        "Content": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                       }
            else:
                data = {
                        "SignatureType": "CMS",
                        "VerifyParams": {"VerifyAll": 1},
                        "Source": "'{doc_in_base64}'".format(doc_in_base64 = doc_in_base64),
                        "Content": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                       }

            return data



        def json_get_signers_info(self, sign_in_base64, sign_type = 5):
            if sign_type != 3 and sign_type != 4:
                sign_type = 5

            data = {
                    "SignatureType": "'{sign_type}'".format(sign_type = sign_type),
                    "Content": "'{sign_in_base64}'".format(sign_in_base64 = sign_in_base64)
                   }

            return data


        def json2xml(self, json_file):
            try:
                return dicttoxml(json_file, attr_type=False)
            except TypeError:
                return '<Error>Exception in method json2xml. Unsupported data type ({error_type})</Error>'.format(error_type = type(json_file))
