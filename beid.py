#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from pprint import pprint
from smartcard.System import readers
from smartcard.Exceptions import NoCardException, CardConnectionException

MAP_MOIS = {
    "JANV": "01", "JAN": "01",
    "FEVR": "02", "FEV": "02",
    "MARS": "03", "MAR": "03",
    "AVRI": "04", "AVR": "04",
    "MAI": "05",
    "JUIN": "06",
    "JUIL": "07",
    "AOUT": "08", "AOU": "08",
    "SEPT": "09", "SEP": "09",
    "OCTO": "10", "OCT": "10",
    "NOVE": "11", "NOV": "11",
    "DECE": "12", "DEC": "12"
}

ID = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31]
ADDRESS = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33]
PHOTO = [0x3F, 0x00, 0xDF, 0x01, 0x40, 0x35]

class CardReader:
    def __init__(self) -> None:
        try:
            self._cnx = readers()[0].createConnection()
            self._cnx.connect()
        except IndexError:
            raise RuntimeError("Pas de lecteur disponible")
        except NoCardException:
            raise RuntimeError("Pas de carte disponible")
        except CardConnectionException as e:
            raise RuntimeError(f"Erreur de connexion à la carte: {e}")

    def _send_apdu(self, apdu):
        response, sw1, sw2 = self._cnx.transmit(apdu)
        return response, sw1, sw2

    def _read_data(self, file_id):
        cmd = [0x00, 0xA4, 0x08, 0x0C, len(file_id)] + file_id
        _, sw1, sw2 = self._send_apdu(cmd)
        if sw1 == 0x6C:
            cmd = [0x00, 0xB0, 0x00, 0x00, sw2]
        else:
            cmd = [0x00, 0xB0, 0x00, 0x00, 256]
        data, sw1, sw2 = self._send_apdu(cmd)
        if sw1 == 0x6C:
            cmd = [0x00, 0xB0, 0x00, 0x00, sw2]
            data, sw1, sw2 = self._send_apdu(cmd)
        return data, sw1, sw2

    def _parse_information(self, data, num_info_limit):
        idx = 0
        infos = []
        while len(infos) <= num_info_limit:
            num_info = data[idx]
            idx += 1
            len_info = data[idx]
            idx += 1
            chaine_bytes = data[idx:idx + len_info]
            idx += len_info
            try:
                infos.append(bytes(chaine_bytes).decode("utf-8"))
            except UnicodeDecodeError:
                infos.append("")
        return infos

    def _parse_date(self, date_str):
        jour, mois, annee = date_str.split()
        mois = MAP_MOIS.get(mois, "01")
        return datetime.strptime(f"{jour}/{mois}/{annee}", "%d/%m/%Y")

    def read_informations(self, photo=False):
        data, sw1, sw2 = self._read_data(ID)
        infos = self._parse_information(data, 12)

        informations = {
            "num_carte": infos[0],
            "debut_val": datetime.strptime(infos[2], "%d.%m.%Y"),
            "fin_val": datetime.strptime(infos[3], "%d.%m.%Y"),
            "commune_delivrance": infos[4],
            "num_nat": infos[5],
            "nom": infos[6],
            "prenoms": infos[7],
            "suffixe": infos[8],
            "nationalite": infos[9],
            "lieu_naissance": infos[10],
            "date_naissance": self._parse_date(infos[11]),
            "sexe": infos[12],
        }

        data, sw1, sw2 = self._read_data(ADDRESS)
        address_infos = self._parse_information(data, 2)

        informations["adresse"] = address_infos[0]
        informations["code_postal"] = address_infos[1]
        informations["localite"] = address_infos[2]

        if photo:
            photo_data = self._read_photo()
            informations["photo"] = photo_data

        for attribute, value in informations.items():
            setattr(self, attribute, value)

        return informations

    def _read_photo(self):
        data, sw1, sw2 = self._read_data(PHOTO)
        photo_bytes = []
        offset = 0
        while sw1 == 0x90:
            cmd = [0x00, 0xB0, offset, 0x00, 256]
            data, sw1, sw2 = self._send_apdu(cmd)
            photo_bytes.extend(data)
            offset += 1
        if sw1 == 0x6C:
            offset -= 1
            cmd = [0x00, 0xB0, offset, 0x00, sw2]
            data, sw1, sw2 = self._send_apdu(cmd)
            photo_bytes.extend(data)
        return bytearray(photo_bytes)

if __name__ == '__main__':
    cr = CardReader()
    pprint(cr.read_informations(False))
