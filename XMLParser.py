import xmltodict
import xml.etree.ElementTree as ET

class XMLParser:
    def xml2json(self, xml):
        try:
            json_data = json.loads(json.dumps(xmltodict.parse(xml)))
            if 'root' in json_data.keys():
                return json_data["root"]
            else:
                return json_data
        except TypeError:
            return '<Error>Exception in method xml2json. Unsupported data type ({error_type})</Error>'.format(error_type = type(xml))

    def is_final(self, xml):
        isFinal = False

        tree = ET.fromstring(xml)
        for child in tree.iter('IsFinal'):
            if child.text == 'True' or child.text == 'true':
                isFinal = True

        return isFinal

    def refid_exist_in_response(self, xml):
        tree = ET.fromstring(xml)

        if tree.findall('Challenge/ContextData/RefId') == []:
            return False
        return True




    def get_token_from_response(self, xml):
        try:
            tree = ET.fromstring(xml)

            for child in tree.iter('AccessToken'):
                return str(child.text)
        except Exception as ex:
            return ('Exception in method: "get_token_from_response": ' + str(ex))

    def get_otoken_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child in tree.iter('access_token'):
            return str(child.text)

    def get_orefresh_token_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child in tree.iter('refresh_token'):
            return str(child.text)

    def get_refid_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child1 in tree.iter('Challenge'):
            for child2 in tree.iter('ContextData'):
                for child3 in tree.iter('RefID'):
                    return child3.text

    def get_refid_expires_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child1 in tree.iter('Challenge'):
            for child2 in tree.iter('TextChallenge'):
                for child3 in tree.iter('ExpiresIn'):
                    return child3.text

    def get_token_expires_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child in tree.iter('ExpiresIn'):
            return child.text

    def get_otoken_expires_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child in tree.iter('expires_in'):
            return str(child.text)

    def get_tr_id_from_response(self, xml):
        tree = ET.fromstring(xml)

        for child in tree.iter('root'):
            return str(child.text)

    def is_signature_valid(self, sig_verify_xml):
        self.debug('IS_SIGNATURE_VALID start')

        isFinal = False

        tree = ET.fromstring(sig_verify_xml)
        for child in tree.iter('row'):
            for child2 in tree.iter('Result'):
                if child2.text == 'True' or child2.text == 'true':
                    isFinal = True

        return isFinal
